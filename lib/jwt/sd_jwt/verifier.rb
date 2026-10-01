# frozen_string_literal: true

module JWT
  module SDJWT
    # Verifies an SD-JWT presentation per RFC 9901 section 6.
    #
    # The issuer JWT signature is verified with the existing JWA/key interfaces
    # (strings, OpenSSL keys or JWT::JWK). Disclosures are checked against the
    # digests and the resulting claims contain only what was actually disclosed.
    #
    # Verification rejects:
    #
    # * duplicate digests / duplicate disclosures,
    # * disclosures that are not referenced by any digest,
    # * disclosures that would overwrite a plain claim,
    # * illegal nesting such as "_sd" inside arrays, "..." inside objects,
    #   "_sd_alg" below the root or recursive disclosure cycles.
    #
    # A Key Binding JWT, when required or present, is checked for audience,
    # nonce, iat and the "sd_hash" and verified with the public key from the
    # issuer signed "cnf.jwk" claim.
    class Verifier
      # @param serialized_sd_jwt [String, CompoundSdJwt] the presented SD-JWT.
      # @param key [String, OpenSSL::PKey::PKey, JWT::JWK::KeyBase] the issuer verification key.
      # @param algorithm [String, Array<String>, Object] expected issuer algorithm(s), defaults to HS256.
      # @param claims [Array<Symbol>, Hash] issuer JWT claims to verify, defaults to +[:exp]+.
      # @param key_finder [#call] optional dynamic key finder for the issuer JWT.
      # @param audience [String, Array<String>, nil] expected Key Binding JWT audience.
      # @param nonce [String, nil] expected Key Binding JWT nonce.
      # @param bind_key [Object, nil] explicit key for verifying the Key Binding JWT
      #   (defaults to the cnf.jwk embedded by the issuer).
      def initialize(serialized_sd_jwt, key: nil, algorithm: 'HS256', claims: :default,
                     key_finder: nil, audience: nil, nonce: nil, bind_key: nil)
        @sd_jwt = serialized_sd_jwt.is_a?(CompoundSdJwt) ? serialized_sd_jwt : CompoundSdJwt.parse(serialized_sd_jwt)
        @key = key
        @algorithm = algorithm
        @claims = claims
        @key_finder = key_finder
        @audience = audience
        @nonce = nonce
        @bind_key = bind_key
      end

      # Performs the full verification.
      #
      # @return [VerificationResult] the verification result.
      # @raise [JWT::VerificationError, JWT::SDJWTError] if verification fails.
      def verify
        verify_issuer_signature
        verify_issuer_claims

        issuer_payload = @sd_jwt.encoded_token.unverified_payload
        validate_issuer_payload_structure(issuer_payload)
        validate_issuer_header

        @digest_algorithm = issuer_payload['_sd_alg'] || DEFAULT_SD_ALG
        @seen_digests = []
        disclosures_by_digest = parse_disclosures

        claims = extract_claims(issuer_payload, disclosures_by_digest, root: true)
        assert_all_disclosures_referenced!(disclosures_by_digest)
        kb_payload = verify_key_binding if kb_required? || @sd_jwt.kb_jwt

        build_result(claims, kb_payload)
      end

      def build_result(claims, kb_payload)
        VerificationResult.new(claims: claims,
                               header: @sd_jwt.encoded_token.header,
                               disclosures: @presented_disclosures,
                               key_binding: kb_payload)
      end

      private

      def verify_issuer_claims
        claims_to_check = @claims == :default ? [:exp] : @claims
        return if claims_to_check.nil? || claims_to_check == false || Array(claims_to_check).empty?

        @sd_jwt.encoded_token.verify_claims!(*Array(claims_to_check))
      end

      def assert_all_disclosures_referenced!(disclosures_by_digest)
        unused = disclosures_by_digest.keys - @referenced_digests
        return if unused.empty?

        raise JWT::SDJWTVerificationError, 'SD-JWT contains disclosures that are not referenced'
      end

      def verify_issuer_signature
        if @key_finder
          @sd_jwt.encoded_token.verify_signature!(algorithm: @algorithm, key_finder: @key_finder)
        else
          raise JWT::VerificationError, 'No verification key available' unless @key

          @sd_jwt.encoded_token.verify_signature!(algorithm: @algorithm, key: @key)
        end
      end

      def validate_issuer_header
        typ = @sd_jwt.encoded_token.header['typ']
        return if typ.nil?

        normalized = typ.downcase
        return if normalized == 'sd-jwt'
        # Application profile types such as "vc+sd-jwt" are accepted.
        return if normalized.end_with?('+sd-jwt')

        raise JWT::SDJWTVerificationError, "Unexpected issuer JWT typ header: #{typ}"
      end

      def validate_issuer_payload_structure(payload)
        unless payload.is_a?(::Hash)
          raise JWT::SDJWTVerificationError, 'Issuer JWT payload must be a JSON object'
        end

        alg = payload['_sd_alg']
        return if alg.nil?
        return if alg.is_a?(::String) && DIGEST_ALGORITHMS.key?(alg)

        raise JWT::SDJWTVerificationError, "Unsupported _sd_alg: #{alg.inspect}"
      end

      def parse_disclosures
        @presented_disclosures = @sd_jwt.disclosures
        @referenced_digests = []

        digests = {}
        @presented_disclosures.each do |disclosure|
          digest = disclosure.digest(@digest_algorithm)
          if digests.key?(digest)
            raise JWT::SDJWTVerificationError, 'SD-JWT contains duplicate disclosure digests'
          end

          digests[digest] = disclosure
        end
        digests
      end

      def extract_claims(value, disclosures_by_digest, root:, active_digests: [])
        case value
        when ::Hash
          extract_from_hash(value, disclosures_by_digest, root, active_digests)
        when ::Array
          extract_from_array(value, disclosures_by_digest, active_digests)
        else
          value
        end
      end

      def extract_from_hash(hash, disclosures_by_digest, root, active_digests)
        hash.each_with_object({}) do |(key, member), result|
          case key
          when '_sd_alg'
            raise JWT::SDJWTVerificationError, 'Illegal nested "_sd_alg" claim' unless root
            # The digest algorithm claim is metadata, never a disclosed claim.
          when '_sd'
            process_sd_member(member, disclosures_by_digest, result, active_digests)
          when '...'
            raise JWT::SDJWTVerificationError, 'Illegal "..." marker inside an object'
          else
            add_plain_claim(key, member, result, disclosures_by_digest, active_digests)
          end
        end
      end

      def add_plain_claim(key, member, result, disclosures_by_digest, active_digests)
        if result.key?(key)
          raise JWT::SDJWTVerificationError, "Disclosed claim #{key.inspect} overwrites an existing claim"
        end

        result[key] = extract_claims(member, disclosures_by_digest, root: false,
                                                                     active_digests: active_digests)
      end

      def process_sd_member(member, disclosures_by_digest, result, active_digests)
        unless member.is_a?(::Array)
          raise JWT::SDJWTVerificationError, 'Illegal "_sd" member: must be an array'
        end

        member.each do |digest|
          unless digest.is_a?(::String)
            raise JWT::SDJWTVerificationError, 'Illegal "_sd" member: digests must be strings'
          end

          if @seen_digests.include?(digest)
            raise JWT::SDJWTVerificationError, 'Duplicate disclosure digest in issuer signed claims'
          end
          @seen_digests << digest

          disclosure = disclosures_by_digest[digest]
          next unless disclosure # digest without disclosure: the claim stays hidden

          if disclosure.claim_name.nil?
            raise JWT::SDJWTVerificationError, 'Array element disclosure referenced from an object'
          end

          if active_digests.include?(digest)
            raise JWT::SDJWTVerificationError, 'Recursive disclosure cycle detected'
          end

          if @referenced_digests.include?(digest)
            raise JWT::SDJWTVerificationError, 'Disclosure digest referenced more than once'
          end

          if result.key?(disclosure.claim_name)
            raise JWT::SDJWTVerificationError,
                  "Disclosed claim #{disclosure.claim_name.inspect} overwrites an existing claim"
          end

          @referenced_digests << digest
          result[disclosure.claim_name] =
            extract_claims(disclosure.value, disclosures_by_digest, root: false,
                                                                     active_digests: active_digests + [digest])
        end
      end

      def extract_from_array(array, disclosures_by_digest, active_digests)
        array.flat_map do |element|
          if element.is_a?(::Hash) && element.key?('...')
            value = resolve_array_digest(element, disclosures_by_digest, active_digests)
            value.nil? ? [] : [value]
          else
            if element.is_a?(::Hash) && (element.key?('_sd') || element.key?('_sd_alg'))
              raise JWT::SDJWTVerificationError, 'Illegal "_sd"/"_sd_alg" member inside an array'
            end

            [extract_claims(element, disclosures_by_digest, root: false, active_digests: active_digests)]
          end
        end
      end

      def resolve_array_digest(marker, disclosures_by_digest, active_digests)
        unless marker.length == 1
          raise JWT::SDJWTVerificationError, 'Array disclosure marker must only contain the "..." member'
        end

        digest = marker['...']
        unless digest.is_a?(::String)
          raise JWT::SDJWTVerificationError, 'Illegal "..." marker: digest must be a string'
        end

        if @seen_digests.include?(digest)
          raise JWT::SDJWTVerificationError, 'Duplicate disclosure digest in issuer signed claims'
        end
        @seen_digests << digest

        disclosure = disclosures_by_digest[digest]
        unless disclosure
          # An undisclosed array element must be removed entirely.
          return nil
        end

        unless disclosure.claim_name.nil?
          raise JWT::SDJWTVerificationError, 'Object member disclosure referenced from an array'
        end

        if active_digests.include?(digest)
          raise JWT::SDJWTVerificationError, 'Recursive disclosure cycle detected'
        end

        if @referenced_digests.include?(digest)
          raise JWT::SDJWTVerificationError, 'Disclosure digest referenced more than once'
        end

        @referenced_digests << digest
        extract_claims(disclosure.value, disclosures_by_digest, root: false, active_digests: active_digests + [digest])
      end

      def kb_required?
        !@audience.nil? || !@nonce.nil?
      end

      def verify_key_binding
        unless @sd_jwt.kb_jwt
          raise JWT::SDJWTVerificationError, 'Key Binding JWT is required but not present'
        end

        kb_token =
          begin
            ::JWT::EncodedToken.new(@sd_jwt.kb_jwt)
          rescue ArgumentError
            raise JWT::SDJWTFormatError, 'Key Binding JWT is malformed'
          end

        verify_kb_header(kb_token)
        kb_payload = verify_kb_signature(kb_token)
        verify_kb_claims(kb_payload)
        verify_sd_hash(kb_payload)

        kb_payload
      end

      def verify_kb_header(kb_token)
        unless kb_token.header.is_a?(::Hash)
          raise JWT::SDJWTFormatError, 'Key Binding JWT header must be a JSON object'
        end

        if kb_token.header['alg'].nil? || kb_token.header['alg'] == 'none'
          raise JWT::SDJWTVerificationError, 'Key Binding JWT must use a MAC or signature algorithm'
        end

        return if kb_token.header['typ'] == 'kb+jwt'

        raise JWT::SDJWTVerificationError, 'Key Binding JWT typ header must be "kb+jwt"'
      end

      def verify_kb_signature(kb_token)
        kb_token.verify_signature!(algorithm: kb_token.header['alg'], key: key_binding_key)
        kb_token.unverified_payload
      end

      def key_binding_key
        return @bind_key if @bind_key

        cnf = @sd_jwt.encoded_token.unverified_payload['cnf']
        unless cnf.is_a?(::Hash) && cnf['jwk'].is_a?(::Hash)
          raise JWT::SDJWTVerificationError, 'Cannot verify Key Binding JWT without a cnf.jwk claim'
        end

        jwk = ::JWT::JWK.create_from(cnf['jwk'])
        jwk.verify_key
      end

      def verify_kb_claims(kb_payload)
        unless kb_payload.is_a?(::Hash)
          raise JWT::SDJWTVerificationError, 'Key Binding JWT payload must be a JSON object'
        end

        raise JWT::SDJWTVerificationError, 'Key Binding JWT is missing "iat"' unless kb_payload['iat'].is_a?(::Numeric)
        raise JWT::SDJWTVerificationError, 'Key Binding JWT is missing "sd_hash"' unless kb_payload['sd_hash'].is_a?(::String)

        if @audience
          aud = kb_payload['aud']
          accepted = Array(aud)
          expected = Array(@audience)
          unless aud && expected.any? { |value| accepted.include?(value) }
            raise JWT::SDJWTVerificationError, 'Key Binding JWT audience does not match'
          end
        else
          raise JWT::SDJWTVerificationError, 'Key Binding JWT is missing "aud"' unless kb_payload.key?('aud')
        end

        if @nonce
          unless kb_payload['nonce'] == @nonce
            raise JWT::SDJWTVerificationError, 'Key Binding JWT nonce does not match'
          end
        else
          raise JWT::SDJWTVerificationError, 'Key Binding JWT is missing "nonce"' unless kb_payload.key?('nonce')
        end
      end

      def verify_sd_hash(kb_payload)
        prefix = CompoundSdJwt.new(issuer_jwt: @sd_jwt.issuer_jwt,
                                   disclosures: @sd_jwt.disclosures).to_s
        expected = Digestable.new(@digest_algorithm).digest(prefix)

        return if secure_compare(expected, kb_payload['sd_hash'])

        raise JWT::SDJWTVerificationError, 'Key Binding JWT sd_hash does not match the presentation'
      end

      def secure_compare(left, right)
        return false unless left.bytesize == right.bytesize

        left.bytes.zip(right.bytes).reduce(0) { |acc, (a, b)| acc | (a ^ b) }.zero?
      end
    end
  end
end
