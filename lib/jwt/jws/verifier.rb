# frozen_string_literal: true

module JWT
  module JWS
    # Verifies JWS JSON Serializations against caller supplied keys and a policy.
    #
    # @api private
    class Verifier
      KeySpec = Struct.new(:key, :identity)

      # @param data [Hash, String] the JWS JSON Serialization.
      # @param algorithms [Array<String>] the caller controlled algorithm whitelist.
      # @param keys [Array] fixed verification keys.
      # @param signers [Array<Hash, JWT::JWS::Signature>] per kid verification specs.
      # @param keyfinder [Proc, nil] resolves a key from a signature header.
      # @param policy [Symbol, Integer, Hash] the acceptance policy.
      # @param options [Hash] claim verification options and understood critical headers.
      def initialize(data, algorithms: nil, keys: nil, signers: nil, keyfinder: nil, policy: nil, **options)
        @data = data
        @algorithms = Array(algorithms).map(&:to_s)
        @fixed_keys = Array(keys)
        @keyfinder = keyfinder
        @options = JWT.configuration.decode.to_h.merge(options)
        @known_crit = Array(@options[:crit]) | ['b64']

        @specified_signers = normalize_signers(signers)
        @pool_mode = @specified_signers.empty?
        expected = @pool_mode ? 0 : @specified_signers.size
        @policy = Policy.from(policy, expected, fixed_keys: @pool_mode)
        @parsed = false
      end

      # Verifies every signature and the claims, without raising for policy failures.
      #
      # @return [JWT::JWS::VerificationResult]
      def verify
        raise ::JWT::IncorrectAlgorithm, 'An algorithm must be specified' if @algorithms.empty?

        parse!

        results = @raw_members.map.with_index { |member, index| verify_member(member, index) }
        valid = results.select(&:valid?)
        distinct_identities = valid.map(&:identity).uniq.size
        satisfied, message = @policy.satisfied?(valid.size, results.size - valid.size, distinct_identities)

        return finish(results, message) unless satisfied

        verify_claims!(results)
      end

      # Verifies and returns the claims, raising when the policy is not met.
      #
      # @return [Array<Hash>] the decoded payload and the header of a verified signature.
      # @raise [JWT::Error] when the serialization, the claims or the policy is invalid.
      def decode
        parse!

        result = verify
        return [result.payload, result.header] if result.verified?

        raise ::JWT::VerificationError, result.error
      end

      private

      def parse!
        return if @parsed

        @encoded_payload, @raw_members = Serializer.parse(@data)
        @parsed = true
      end

      def finish(results, message)
        VerificationResult.new(encoded_payload: @encoded_payload,
                               signatures: results,
                               verified: false,
                               error: message)
      end

      def normalize_signers(signers)
        Array(signers).map do |spec|
          signature = spec.is_a?(Signature) ? spec : Signature.from(spec)
          { signature: signature, identity: identity_of(signature.key) }
        end
      end

      def verify_member(member, index)
        encoded_header = member['protected']
        unprotected = member['header']
        encoded_signature = member['signature']

        validate_member_structure!(encoded_header, unprotected, encoded_signature)
        header = member_header(encoded_header, unprotected)
        validate_alg!(header)
        validate_crit!(header)

        identity = verify_signature!(header, encoded_header, encoded_signature)

        SignatureResult.new(index: index, header: header, valid: true, identity: identity)
      rescue ::JWT::Error => e
        build_failed_result(index, member, e.message)
      end

      def validate_member_structure!(encoded_header, unprotected, encoded_signature)
        raise ::JWT::MalformedTokenError, 'Signature is missing the protected header' unless encoded_header.is_a?(::String)
        if unprotected && !unprotected.is_a?(::Hash)
          raise ::JWT::MalformedTokenError, 'The unprotected header must be a JSON object'
        end
        raise ::JWT::MalformedTokenError, 'Signature is missing the signature value' unless encoded_signature.is_a?(::String)
      end

      def member_header(encoded_header, unprotected)
        merge_headers(decode_header(encoded_header), unprotected)
      end

      def decode_header(encoded_header)
        header = ::JWT::JSON.parse(::JWT::Base64.url_decode(encoded_header))
        raise ::JWT::MalformedTokenError, 'The protected header must be a JSON object' unless header.is_a?(::Hash)

        header
      end

      # RFC 7515 section 7.2.1: the Header Parameter MUST NOT be present in
      # both the protected and the unprotected header.
      def merge_headers(protected_header, unprotected_header)
        unprotected_header ||= {}
        overlap = protected_header.keys & unprotected_header.keys
        unless overlap.empty?
          raise ::JWT::MalformedTokenError, "Header parameters must not be repeated in protected and unprotected headers: #{overlap.join(', ')}"
        end

        unprotected_header.merge(protected_header)
      end

      def validate_alg!(header)
        alg = header['alg']
        raise ::JWT::IncorrectAlgorithm, 'Token is missing alg header' unless alg.is_a?(::String)
        raise ::JWT::IncorrectAlgorithm, 'Expected a different algorithm' unless @algorithms.include?(alg)
      end

      # RFC 7515 section 4.1.11: unknown crit parameters cannot be ignored and
      # every critical parameter has to be present in the header.
      def validate_crit!(header)
        crit = header['crit']
        return unless crit

        validate_crit_structure!(crit)
        validate_crit_presence!(header, crit)
        validate_crit_known!(crit)
      end

      def validate_crit_structure!(crit)
        raise ::JWT::InvalidCritError, 'Crit header should be an array' unless crit.is_a?(::Array)
        raise ::JWT::InvalidCritError, 'Crit header must not be empty' if crit.empty?
        unless crit.all? { |name| name.is_a?(::String) }
          raise ::JWT::InvalidCritError, 'Crit header values must be strings'
        end
        raise ::JWT::InvalidCritError, 'Crit header must not contain duplicates' if crit.uniq.size != crit.size
      end

      def validate_crit_presence!(header, crit)
        missing_from_header = crit - header.keys
        return if missing_from_header.empty?

        raise ::JWT::InvalidCritError, "Crit header values are not present in the header: #{missing_from_header.join(', ')}"
      end

      def validate_crit_known!(crit)
        unknown = crit - @known_crit
        return if unknown.empty?

        raise ::JWT::InvalidCritError, "Unknown critical header parameters cannot be ignored: #{unknown.join(', ')}"
      end

      def verification_keys(header)
        if @specified_signers.any?
          [resolve_named_keyspec(header)]
        elsif @keyfinder
          key = call_keyfinder(header)
          raise ::JWT::SignatureError, 'No verification key available' unless key

          [KeySpec.new(key, identity_of(key))]
        else
          raise ::JWT::SignatureError, 'No verification key available' if @fixed_keys.empty?

          @fixed_keys.map { |key| KeySpec.new(key, identity_of(key)) }
        end
      end

      def resolve_named_keyspec(header)
        kid = header['kid']
        match = @specified_signers.find { |entry| entry[:signature].kid == kid }
        raise ::JWT::SignatureError, "No verification key available for kid #{kid.inspect}" unless match

        KeySpec.new(match[:signature].key, match[:identity])
      end

      def call_keyfinder(header)
        key = if @keyfinder.arity == 2
                @keyfinder.call(header, unverified_payload)
              else
                @keyfinder.call(header)
              end
        Array(key).first
      end

      def verify_signature!(header, encoded_header, encoded_signature)
        signing_input = [encoded_header, @encoded_payload].join('.')
        signature_bytes = ::JWT::Base64.url_decode(encoded_signature)

        matching = verification_keys(header).find do |spec|
          verifiers = JWA.create_verifiers(algorithms: @algorithms,
                                           keys: Array(spec.key),
                                           preferred_algorithm: header['alg'])
          next false if verifiers.empty?

          verifiers.any? { |verifier| verifier.verify(data: signing_input, signature: signature_bytes) }
        end

        raise ::JWT::VerificationError, 'Signature verification failed' unless matching

        matching.identity
      end

      def verify_claims!(results)
        Claims::DecodeVerifier.verify!(unverified_payload, @options)
        VerificationResult.new(encoded_payload: @encoded_payload,
                               signatures: results,
                               verified: true)
      rescue ::JWT::Error => e
        VerificationResult.new(encoded_payload: @encoded_payload,
                               signatures: results,
                               verified: false,
                               error: e.message)
      end

      def unverified_payload
        ::JWT::JSON.parse(::JWT::Base64.url_decode(@encoded_payload))
      end

      def identity_of(key)
        [key.class, key.object_id]
      end

      def build_failed_result(index, member, message)
        header = safe_header(member)
        SignatureResult.new(index: index, header: header, valid: false, error: message)
      end

      def safe_header(member)
        protected_header = decode_header_safely(member['protected'])
        unprotected_header = member['header'].is_a?(::Hash) ? member['header'] : {}
        return unprotected_header unless protected_header.is_a?(::Hash)

        unprotected_header.merge(protected_header) { |_name, unprotected, _protected| unprotected }
      end

      def decode_header_safely(encoded_header)
        return {} unless encoded_header.is_a?(::String)

        ::JWT::JSON.parse(::JWT::Base64.url_decode(encoded_header))
      rescue ::JWT::Error, ::JSON::ParserError, ArgumentError
        {}
      end
    end
  end
end
