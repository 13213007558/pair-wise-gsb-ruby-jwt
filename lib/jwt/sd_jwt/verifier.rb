# frozen_string_literal: true

module JWT
  module SDJWT
    # Verifies compact SD-JWT presentations according to RFC 9901.
    class Verifier
      ARRAY_DIGEST_KEY = ''

      Result = Struct.new(:claims, :issuer_payload, :header, :disclosures, :key_binding)

      def initialize(token, issuer_key, algorithm:)
        @token = token
        @issuer_key = issuer_key
        @algorithm = algorithm
        @used_digests = Set.new
      end

      def verify!(key_binding: nil)
        issued_jwt, encoded_disclosures, kb_jwt = Compact.parse(@token)
        @header, issuer_payload = verify_issuer_jwt(issued_jwt)
        @hash_algorithm = HashAlgorithm.find(issuer_payload['_sd_alg'])

        disclosures = parse_disclosures(encoded_disclosures)
        @disclosures_by_digest = index_disclosures(disclosures)

        claims = materialize(deep_dup(issuer_payload))
        ensure_all_disclosures_referenced!(disclosures)
        verified_kb = verify_key_binding(kb_jwt, issued_jwt, encoded_disclosures, issuer_payload, key_binding)

        Result.new(claims, issuer_payload, @header, disclosures, verified_kb)
      end

      private

      def verify_issuer_jwt(jwt)
        payload, header = JWT.decode(
          jwt,
          @issuer_key,
          true,
          algorithm: @algorithm
        )
        raise MalformedTokenError, 'Issuer JWT payload must be an object' unless payload.is_a?(::Hash)

        [header, payload]
      end

      def parse_disclosures(encoded_disclosures)
        encoded_disclosures.each_with_object([]) do |encoded, list|
          if list.any? { |disclosure| disclosure.encoded == encoded }
            raise DisclosureVerificationError, 'Duplicate disclosure provided'
          end

          list << Disclosure.new(encoded)
        end
      end

      def index_disclosures(disclosures)
        disclosures.each_with_object({}) do |disclosure, map|
          digest = disclosure.digest(@hash_algorithm)
          if map.key?(digest)
            raise DisclosureVerificationError, "Duplicate disclosure digest: #{digest}"
          end

          map[digest] = disclosure
        end
      end

      def materialize(value)
        case value
        when ::Hash then materialize_object(value)
        when ::Array then materialize_array(value)
        else value
        end
      end

      def materialize_object(object)
        validate_sd_claims!(object)

        result = object.each_with_object({}) do |(key, child), normalized|
          next if key == '_sd'

          normalized[key] = materialize(child)
        end

        Array(object['_sd']).each do |digest|
          disclosure = @disclosures_by_digest[digest]
          next unless disclosure

          consume_disclosure!(digest, disclosure, attribute: true)
          if result.key?(disclosure.key)
            raise DisclosureVerificationError,
                  "Disclosed claim conflicts with existing plaintext claim: #{disclosure.key}"
          end

          result[disclosure.key] = materialize(disclosure.value)
        end
        result
      end

      def materialize_array(array)
        array.map do |child|
          if array_digest_marker?(child)
            digest = child[ARRAY_DIGEST_KEY]
            disclosure = @disclosures_by_digest[digest]
            next child unless disclosure

            consume_disclosure!(digest, disclosure, attribute: false)
            materialize(disclosure.value)
          else
            if child.is_a?(::Hash) && child.key?(ARRAY_DIGEST_KEY)
              raise MalformedTokenError,
                    'An empty claim name is reserved for array disclosure markers'
            end

            materialize(child)
          end
        end
      end

      def consume_disclosure!(digest, disclosure, attribute:)
        if attribute && !disclosure.attribute?
          raise MalformedTokenError, 'Array element disclosure cannot be used for an object claim'
        end
        if !attribute && !disclosure.array_element?
          raise MalformedTokenError, 'Object claim disclosure cannot be used as an array element'
        end
        if @used_digests.include?(digest)
          raise DisclosureVerificationError, "Disclosure referenced more than once: #{digest}"
        end

        @used_digests << digest
      end

      def validate_sd_claims!(object)
        if object.key?(ARRAY_DIGEST_KEY)
          raise MalformedTokenError,
                'An empty claim name is reserved for array disclosure markers'
        end

        sd = object['_sd']
        return if sd.nil?
        unless sd.is_a?(::Array) && sd.all? { |digest| digest.is_a?(::String) }
          raise MalformedTokenError,
                '_sd must be an array of base64url-encoded digest strings'
        end
        if sd.uniq.size != sd.size
          raise DisclosureVerificationError, 'Duplicate digest in signed _sd array'
        end
      end

      def array_digest_marker?(value)
        value.is_a?(::Hash) &&
          value.size == 1 &&
          value.key?(ARRAY_DIGEST_KEY) &&
          value[ARRAY_DIGEST_KEY].is_a?(::String)
      end

      def ensure_all_disclosures_referenced!(disclosures)
        unreferenced = disclosures.reject do |disclosure|
          @used_digests.include?(disclosure.digest(@hash_algorithm))
        end
        return if unreferenced.empty?

        raise DisclosureVerificationError,
              "#{unreferenced.size} disclosure(s) are not referenced by the signed SD-JWT"
      end

      def verify_key_binding(kb_jwt, issued_jwt, encoded_disclosures, issuer_payload, options)
        return nil if options.nil? && kb_jwt.nil?
        raise KeyBindingError, 'Key Binding JWT was not expected' if options.nil?
        raise KeyBindingError, 'Key Binding JWT is missing' unless kb_jwt
        unless options.key?(:now) && !options[:now].nil?
          raise KeyBindingError, 'now must be provided for Key Binding verification'
        end

        cnf_jwk = issuer_payload.dig('cnf', 'jwk')
        unless cnf_jwk.is_a?(::Hash)
          raise KeyBindingError, 'Issuer JWT cnf.jwk is missing or invalid'
        end

        KeyBinding.verify(
          jwt: kb_jwt,
          cnf_jwk: cnf_jwk,
          presentation_input: Compact.presentation_input(issued_jwt, encoded_disclosures),
          hash_algorithm: @hash_algorithm,
          audience: options.fetch(:audience),
          nonce: options.fetch(:nonce),
          now: options.fetch(:now),
          algorithm: options.fetch(:algorithm, 'ES256'),
          leeway: options.fetch(:leeway, 0)
        )
      end

      def deep_dup(value)
        case value
        when ::Hash
          value.each_with_object({}) { |(key, child), object| object[key] = deep_dup(child) }
        when ::Array
          value.map { |child| deep_dup(child) }
        else
          value
        end
      end
    end
  end
end
