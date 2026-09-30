# frozen_string_literal: true

require_relative '../jwa'
require_relative 'signature'
require_relative 'signature_result'
require_relative 'key_identity'

module JWT
  module JWS
    # Parses and verifies a JWS using the General or Flattened JSON
    # Serialization defined in RFC 7515.
    #
    # Each signature is verified independently and reported through its own
    # {JWT::JWS::SignatureResult}. A caller supplied policy then decides whether
    # the whole JWS is verified.
    class SerializedToken
      # Header parameters defined by the JWS/JWA/JWE specifications that this
      # library understands. Critical parameters outside this list and the
      # caller provided list are rejected.
      REGISTERED_HEADERS = %w[alg jku jwk x5u x5c x5t x5t#S256 kid typ cty crit b64].freeze

      private_constant(:REGISTERED_HEADERS)

      # @return [Array<JWT::JWS::Signature>] the signatures carried by the JWS.
      attr_reader :signatures

      # Parses a JSON serialized JWS.
      #
      # @param json [String, Hash] the General or Flattened JSON Serialization.
      # @return [JWT::JWS::SerializedToken]
      # @raise [JWT::MalformedTokenError] if the serialization is structurally invalid.
      def self.parse(json)
        data = json.is_a?(::String) ? JWT::JSON.parse(json) : json
        raise ::JWT::MalformedTokenError, 'JWS JSON serialization must be a JSON object' unless data.is_a?(::Hash)

        signatures = extract_signatures(data)
        raise ::JWT::MalformedTokenError, 'JWS JSON serialization does not contain any signature' if signatures.empty?

        payload = data['payload']
        raise ::JWT::MalformedTokenError, 'JWS JSON serialization is missing the payload' unless payload.is_a?(::String)

        new(payload: payload, signatures: signatures).tap(&:validate_payload!)
      rescue ::JSON::ParserError
        raise ::JWT::MalformedTokenError, 'Invalid JWS JSON serialization'
      end

      def initialize(payload:, signatures:)
        @encoded_payload = payload
        @signatures = signatures
      end

      # @return [String] the Base64url encoded payload.
      attr_reader :encoded_payload

      # Validates that the payload is Base64url encoded. The JSON contents are
      # only decoded lazily so malformed tokens are still rejected as malformed.
      #
      # @return [void]
      # @raise [JWT::MalformedTokenError] if the payload is not valid Base64url.
      def validate_payload!
        ::JWT::Base64.url_decode(encoded_payload)
        nil
      rescue ::JWT::Base64DecodeError
        raise ::JWT::MalformedTokenError, 'Invalid payload encoding'
      end

      # Verifies every signature independently.
      #
      # @param algorithms [Array<String, Object>] the caller provided algorithm whitelist.
      # @param keys [Array] the keys accepted for verification.
      # @param key_finder [#call, nil] a block resolving the key from a signature.
      # @param known_crit [Array<String>] critical headers understood by the caller.
      # @return [Array<JWT::JWS::SignatureResult>] one result per signature, in order.
      def verify_signatures(algorithms:, keys:, key_finder:, known_crit:)
        signatures.map do |signature|
          verify_one(signature, algorithms, keys, key_finder, Array(known_crit).map(&:to_s))
        end
      end

      # Decodes the payload without verifying any signature.
      #
      # @return [Object] the decoded payload.
      # @raise [JWT::MalformedTokenError] if the payload is not valid Base64url encoded JSON.
      def unverified_payload
        @unverified_payload ||= JWT::JSON.parse(::JWT::Base64.url_decode(encoded_payload))
      rescue ::JSON::ParserError
        raise ::JWT::MalformedTokenError, 'Invalid segment encoding'
      end

      # @return [Hash] the General JSON Serialization members.
      def to_general_hash
        {
          'payload' => encoded_payload,
          'signatures' => signatures.map(&:to_flattened_hash)
        }
      end

      # @return [Hash] the Flattened JSON Serialization members.
      # @raise [JWT::EncodeError] if more than one signature is present.
      def to_flattened_hash
        raise ::JWT::EncodeError, 'Flattened JSON Serialization supports exactly one signature' unless signatures.size == 1

        { 'payload' => encoded_payload }.merge(signatures.first.to_flattened_hash)
      end

      def self.extract_signatures(data)
        if data.key?('signatures')
          entries = data['signatures']
          unless entries.is_a?(::Array) && !entries.empty? && entries.all?(::Hash)
            raise ::JWT::MalformedTokenError, 'The signatures member must be a non-empty array of JSON objects'
          end
          if data.key?('protected') || data.key?('header') || data.key?('signature')
            raise ::JWT::MalformedTokenError, 'General and Flattened JWS JSON Serialization members must not be mixed'
          end

          entries.map { |entry| build_signature(entry) }
        else
          flattened_signature(data)
        end
      end
      private_class_method :extract_signatures

      def self.flattened_signature(data)
        return [] unless data.key?('protected') || data.key?('header') || data.key?('signature')

        [build_signature(data)]
      end
      private_class_method :flattened_signature

      def self.build_signature(entry)
        Signature.new(
          protected_header: entry['protected'],
          header: entry['header'],
          signature: entry['signature']
        )
      end
      private_class_method :build_signature

      private

      def verify_one(signature, algorithms, keys, key_finder, known_crit)
        signature.validate!
        validate_crit!(signature, known_crit)

        alg = signature.header['alg']
        jwa = resolve_algorithm(alg, algorithms)
        key = verify_with_keys(signature, jwa, keys_for(signature, keys, key_finder))

        SignatureResult.new(signature: signature, key: key)
      rescue ::JWT::Error => e
        SignatureResult.new(signature: signature, error: e)
      end

      def resolve_algorithm(alg, algorithms)
        unless alg.is_a?(::String)
          raise ::JWT::IncorrectAlgorithm, 'Token header alg must be a string'
        end

        resolved = Array(algorithms).map { |candidate| JWA.resolve(candidate) }
        jwa = resolved.find { |candidate| candidate.valid_alg?(alg) }
        raise ::JWT::IncorrectAlgorithm, "Algorithm '#{alg}' is not in the allowed algorithms list" unless jwa

        jwa
      rescue ArgumentError => e
        raise ::JWT::IncorrectAlgorithm, e.message
      end

      def keys_for(signature, keys, key_finder)
        resolved = resolve_keys(signature, keys, key_finder)
        raise ::JWT::SignatureError, 'No verification key available' if resolved.empty? && signature.header['alg'] != 'none'

        resolved
      end

      def resolve_keys(signature, keys, key_finder)
        return Array(keys) unless key_finder

        resolved = if key_finder.arity == 2
                     key_finder.call(signature.header, unverified_payload)
                   else
                     key_finder.call(signature)
                   end
        Array(resolved)
      end

      def verify_with_keys(signature, jwa, keys)
        if jwa.is_a?(JWA::None)
          raise ::JWT::VerificationError, 'Signature verification failed' unless signature.signature.empty?

          return signature
        end

        verify_with_actual_keys(signature, jwa, keys)
      end

      def verify_with_actual_keys(signature, jwa, keys)
        jwks, other_keys = keys.partition { |key| key.is_a?(::JWT::JWK::KeyBase) }

        matching_jwk = jwks.find do |jwk|
          next false unless jwk.jwa.valid_alg?(signature.header['alg'])

          jwk.verify(data: signature.signing_input(encoded_payload), signature: signature.signature)
        rescue ::JWT::Error
          false
        end

        if matching_jwk
          return matching_jwk
        end

        verified = other_keys.find do |key|
          jwa.verify(data: signature.signing_input(encoded_payload), signature: signature.signature, verification_key: key)
        rescue ::JWT::Error
          false
        end

        raise ::JWT::VerificationError, 'Signature verification failed' unless verified

        verified
      end

      def validate_crit!(signature, known_crit)
        if signature.unprotected_header&.key?('crit')
          raise ::JWT::InvalidCritError, 'Crit header must be integrity protected'
        end

        crit = signature.header['crit']
        return if crit.nil?

        raise ::JWT::InvalidCritError, 'Crit header must be an array of strings' unless crit.is_a?(::Array) && crit.all?(::String)
        raise ::JWT::InvalidCritError, 'Crit header must not be empty' if crit.empty?
        raise ::JWT::InvalidCritError, 'Crit header values must be unique' if crit.uniq.size != crit.size

        protected = signature.protected_header
        crit.each do |name|
          unless protected&.key?(name)
            raise ::JWT::InvalidCritError, "Critical header '#{name}' must be present in the protected header"
          end
          unless REGISTERED_HEADERS.include?(name) || known_crit.include?(name)
            raise ::JWT::InvalidCritError, "Unknown critical header '#{name}' cannot be ignored"
          end
        end
      end
    end
  end
end
