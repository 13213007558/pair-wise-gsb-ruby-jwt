# frozen_string_literal: true

module JWT
  module SDJwt
    class Verifier
      def initialize(sd_jwt:, issuer_key:, algorithm:, current_time:, audience:, nonce:, holder_key:,
                     key_binding_algorithm:, key_binding_leeway:, claims:)
        @sd_jwt = sd_jwt
        @issuer_key = issuer_key
        @algorithm = algorithm
        @current_time = current_time
        @audience = audience
        @nonce = nonce
        @holder_key = holder_key
        @key_binding_algorithm = key_binding_algorithm
        @key_binding_leeway = key_binding_leeway
        @required_paths = claims || []
      end

      def verify
        parse_and_verify_signature
        verify_sd_algorithm
        payload = reveal_payload
        verify_required_paths(payload)
        kb_payload = verify_key_binding(payload)
        Result.new(
          payload: payload,
          header: @header,
          disclosures: @parsed.disclosures,
          key_binding_payload: kb_payload
        )
      end

      private

      def parse_and_verify_signature
        @parsed = Compact.parse(@sd_jwt)
        encoded = EncodedToken.new(@parsed.jwt)
        encoded.verify_signature!(algorithm: @algorithm, key: @issuer_key)
        @header = encoded.header
        @issuer_payload = encoded.unverified_payload
        @used_disclosures = {}
        @seen_digests = {}
        @disclosures_by_digest = @parsed.disclosures.each_with_object({}) do |disclosure, memo|
          if memo.key?(disclosure.digest)
            raise DuplicateDisclosureError, 'Two disclosures have the same digest'
          end
          memo[disclosure.digest] = disclosure
        end
      end

      def verify_sd_algorithm
        unless @issuer_payload[SD_ALGORITHM_CLAIM] == HASH_ALGORITHM
          raise MalformedTokenError, 'SD-JWT issuer payload must declare _sd_alg as sha-256'
        end
      end

      def reveal_payload
        payload = reveal_hash(@issuer_payload, root: true)
        encoded_digests = @parsed.disclosures.map(&:digest)
        unused = encoded_digests.reject { |digest| @used_disclosures[digest] }
        unless unused.empty?
          raise UnreferencedDisclosureError, 'All disclosures must be referenced by the SD-JWT'
        end

        payload
      end

      def reveal_hash(hash, root: false)
        unless hash.is_a?(Hash)
          raise MalformedTokenError, 'SD claim container must be a JSON object'
        end

        if !root && hash.key?(SD_ALGORITHM_CLAIM)
          raise MalformedTokenError, '_sd_alg is only allowed in the issuer-signed payload root'
        end

        result = {}
        hash.each do |key, value|
          if key == ARRAY_SD_MARKER
            raise MalformedTokenError, 'Array disclosure marker cannot appear in a JSON object'
          end
          next if key == SD_CLAIM || (root && key == SD_ALGORITHM_CLAIM)

          result[key] = reveal_value(value)
        end
        reveal_disclosures(hash[SD_CLAIM], result)
        result
      end

      def reveal_disclosures(raw_digests, result)
        return if raw_digests.nil?
        unless raw_digests.is_a?(Array) && raw_digests.all? { |digest| digest.is_a?(String) }
          raise MalformedTokenError, '_sd must be an array of strings'
        end

        raw_digests.each do |digest|
          if @seen_digests.key?(digest)
            raise DuplicateDisclosureError, 'A disclosure digest appeared more than once in the issuer payload'
          end
          @seen_digests[digest] = true
          next unless @disclosures_by_digest.key?(digest)
          if @used_disclosures.key?(digest)
            raise DuplicateDisclosureError, 'A disclosure digest was referenced more than once'
          end

          disclosure = @disclosures_by_digest.fetch(digest)
          if disclosure.array_element? || disclosure.claim_name == SD_CLAIM || disclosure.claim_name == SD_ALGORITHM_CLAIM
            raise ClaimConflictError, 'Disclosure attempted to inject a reserved claim'
          end
          if result.key?(disclosure.claim_name)
            raise ClaimConflictError, "Disclosed claim #{disclosure.claim_name} conflicts with an existing plaintext claim"
          end

          @used_disclosures[digest] = true
          result[disclosure.claim_name] = reveal_value(disclosure.value)
        end
      end

      def reveal_value(value)
        case value
        when Hash then reveal_hash(value)
        when Array then reveal_array(value)
        else value
        end
      end

      def reveal_array(array)
        unless array.is_a?(Array)
          raise MalformedTokenError, 'Selectively disclosable array content must be a JSON array'
        end

        array.each_with_object([]) do |child, result|
          if marker?(child)
            digest = child[ARRAY_SD_MARKER]
            unless digest.is_a?(String)
              raise MalformedTokenError, 'Array disclosure marker digest must be a string'
            end
            disclosed = @disclosures_by_digest[digest]
            next unless disclosed

            result << reveal_array_element(child)
          else
            result << reveal_value(child)
          end
        end
      end

      def reveal_array_element(marker)
        digest = marker[ARRAY_SD_MARKER]
        unless digest.is_a?(String)
          raise MalformedTokenError, 'Array disclosure marker digest must be a string'
        end

        disclosure = @disclosures_by_digest[digest]
        unless disclosure&.array_element?
          raise MalformedTokenError, 'Array disclosure marker does not reference an array element disclosure'
        end
        if @seen_digests.key?(digest)
          raise DuplicateDisclosureError, 'An array element disclosure was referenced more than once'
        end
        @seen_digests[digest] = true

        @used_disclosures[digest] = true
        reveal_value(disclosure.value)
      end

      def marker?(value)
        value.is_a?(Hash) && value.size == 1 && value.key?(ARRAY_SD_MARKER)
      end

      def verify_required_paths(payload)
        @required_paths.each do |path|
          unless path_present?(payload, normalize_path(path))
            raise ClaimNotFound, "Required claim #{path.is_a?(Array) ? path.join('.') : path} was not disclosed"
          end
        end
      end

      def path_present?(value, path)
        return true if path.empty?

        head, *rest = path
        case value
        when Hash
          value.key?(head) && path_present?(value[head], rest)
        when Array
          head =~ /\A[0-9]+\z/ && head.to_i < value.size && path_present?(value[head.to_i], rest)
        else
          false
        end
      end

      def normalize_path(path)
        path.is_a?(Array) ? path.map(&:to_s) : path.to_s.split('.')
      end

      def verify_key_binding(payload)
        if key_binding_expected? && @parsed.key_binding_jwt.nil?
          raise KeyBindingError, 'Key binding JWT is required but was not presented'
        end
        return nil unless @parsed.key_binding_jwt

        require_key_binding_parameters!
        kb_payload = verified_key_binding_payload(payload)
        verify_key_binding_claims(kb_payload)
        verify_sd_hash(kb_payload)
        kb_payload
      end

      def require_key_binding_parameters!
        return unless @audience.nil? || @nonce.nil?

        raise KeyBindingError, 'Expected audience and nonce are required for key binding verification'
      end

      def verified_key_binding_payload(payload)
        encoded = EncodedToken.new(@parsed.key_binding_jwt)
        unless encoded.header['typ'] == KEY_BINDING_TYPE
          raise KeyBindingError, 'Key binding JWT typ header must be kb+jwt'
        end

        encoded.verify_signature!(algorithm: @key_binding_algorithm, key: holder_key(payload))
        encoded.unverified_payload
      end

      def key_binding_expected?
        @audience || @nonce || @holder_key
      end

      def holder_key(payload)
        cnf = payload['cnf']
        unless cnf.is_a?(Hash)
          raise KeyBindingError, 'Issuer JWT does not contain a cnf claim'
        end

        key = @holder_key || begin
          jwk = cnf['jwk']
          JWT::JWK.create_from(jwk).verify_key if jwk.is_a?(Hash)
        end
        unless key
          raise KeyBindingError, 'Holder key is required to verify the key binding JWT'
        end

        verify_cnf_thumbprint(cnf, key)
        key
      end

      def verify_cnf_thumbprint(cnf, key)
        thumbprint = cnf['jkt']
        if thumbprint
          actual = SDJwt.key_thumbprint(key)
          unless secure_compare(thumbprint, actual)
            raise KeyBindingError, 'Key binding key does not match cnf.jkt'
          end
          return
        end

        jwk = cnf['jwk']
        unless jwk.is_a?(Hash)
          raise KeyBindingError, 'cnf must contain jkt or jwk'
        end

        imported = JWT::JWK.create_from(jwk)
        unless secure_compare(SDJwt.key_thumbprint(imported.verify_key), SDJwt.key_thumbprint(key))
          raise KeyBindingError, 'Key binding key does not match cnf.jwk'
        end
      end

      def verify_key_binding_claims(kb_payload)
        unless audience_matches?(kb_payload['aud'], @audience)
          raise KeyBindingError, 'Key binding audience does not match'
        end
        unless @nonce.nil? || secure_compare(kb_payload['nonce'].to_s, @nonce.to_s)
          raise KeyBindingError, 'Key binding nonce does not match'
        end
        unless kb_payload['iat'].is_a?(Numeric)
          raise KeyBindingError, 'Key binding iat must be a numeric time'
        end

        leeway = @key_binding_leeway.to_i
        if kb_payload['iat'] > @current_time.to_i + leeway
          raise KeyBindingError, 'Key binding iat is in the future'
        end
      end

      def audience_matches?(actual, expected)
        return true if expected.nil?

        Array(actual).include?(expected)
      end

      def verify_sd_hash(kb_payload)
        actual = kb_payload['sd_hash']
        expected = SDJwt.sd_hash(@parsed.key_binding_input)
        unless actual.is_a?(String) && secure_compare(actual, expected)
          raise KeyBindingError, 'Key binding sd_hash does not match the presented SD-JWT'
        end
      end

      def secure_compare(left, right)
        return false unless left.is_a?(String) && right.is_a?(String)
        return false unless left.bytesize == right.bytesize

        left.bytes.zip(right.bytes).inject(0) { |result, (a, b)| result | (a ^ b) }.zero?
      end
    end
  end
end
