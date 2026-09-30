# frozen_string_literal: true

module JWT
  module SDJWT
    # Transforms claims into an SD-JWT issuer payload and signs the JWT.
    class Issuer
      RESERVED_KEYS = %w[_sd _sd_alg].freeze
      ARRAY_DIGEST_KEY = ''

      Result = Struct.new(:jwt, :sd_jwt, :disclosures, :claims, :holder_jwk) do
        def to_s
          sd_jwt
        end
      end

      def initialize(payload:, signer_key:, algorithm: 'ES256', header_fields: {}, disclosable_paths: [], # rubocop:disable Metrics/ParameterLists
                     decoys: 0, holder_jwk: nil, sd_alg: 'sha-256', rng: SecureRandom, salt_bytes: 16)
        @original_payload = normalize(payload)
        @signer_key = signer_key
        @algorithm = algorithm
        @header_fields = header_fields
        @paths = normalize_paths(disclosable_paths)
        @decoys = decoys
        @holder_jwk = canonical_jwk(holder_jwk)
        @hash_algorithm = HashAlgorithm.find(sd_alg)
        @rng = rng
        @salt_bytes = salt_bytes
        @disclosures = []
        validate_options!
      end

      def issue
        validate_paths!
        claims = deep_dup(@original_payload)
        transformed = transform_value(claims, [], true)
        raise SDJWT::Error, 'Issuer payload must be a JSON object' unless transformed.is_a?(::Hash)

        transformed['cnf'] = { 'jwk' => @holder_jwk } if @holder_jwk
        transformed['_sd_alg'] = @hash_algorithm.name
        jwt = JWT.encode(transformed, @signer_key, @algorithm, @header_fields)
        sd_jwt = Compact.serialize(jwt, @disclosures.map(&:encoded))
        Result.new(jwt, sd_jwt, @disclosures, transformed, @holder_jwk)
      end

      private

      def transform_value(value, path, root = false, protected_value = false)
        case value
        when ::Hash
          transform_object(value, path, root, protected_value)
        when ::Array
          transform_array(value, path, protected_value)
        else
          value
        end
      end

      def transform_object(object, path, root, protected_value)
        if !root && !protected_value
          marker = object[ARRAY_DIGEST_KEY]
          raise SDJWT::Error, 'An empty claim name is reserved for array disclosure markers' if marker
        end

        transformed = object.each_with_object({}) do |(key, child), result|
          child_path = path + [key]
          child_protected = protected_value || (key == 'cnf' && path.empty?)
          transformed_child = transform_value(child, child_path, false, child_protected)
          if child_protected
            result[key] = transformed_child
          elsif @paths.include?(child_path)
            disclose_attribute(result, key, transformed_child)
          else
            result[key] = transformed_child
          end
        end
        add_decoy_digests(transformed, path) unless protected_value
        transformed
      end

      def transform_array(array, path, protected_value)
        transformed = array.each_with_index.map do |child, index|
          child_path = path + [index.to_s]
          transformed_child = transform_value(child, child_path, false, protected_value)
          if !protected_value && @paths.include?(child_path)
            disclose_array_element(transformed_child)
          else
            transformed_child
          end
        end
        return transformed if protected_value

        transformed.concat(decoy_digests(path).map { |digest| { ARRAY_DIGEST_KEY => digest } })
      end

      def disclose_attribute(object, key, value)
        object['_sd'] ||= []
        object['_sd'] << create_disclosure(key, value).digest(@hash_algorithm)
      end

      def disclose_array_element(value)
        { ARRAY_DIGEST_KEY => create_disclosure(nil, value).digest(@hash_algorithm) }
      end

      def create_disclosure(key, value)
        salt = Disclosure.salt(@rng, @salt_bytes)
        Disclosure.create(key, value, salt: salt).tap { |disclosure| @disclosures << disclosure }
      end

      def add_decoy_digests(object, path)
        digests = object['_sd'] || []
        digests.concat(decoy_digests(path))
        return if digests.empty?

        object['_sd'] = digests.shuffle(random: @rng)
      end

      def decoy_digests(path)
        Array.new(decoy_count(path)) { random_digest }
      end

      def decoy_count(path)
        case @decoys
        when ::Integer
          validate_decoy_count!(@decoys)
        when ::Hash
          validate_decoy_count!(Integer(@decoys[path] || @decoys[path.map(&:to_sym)] || 0))
        else
          raise SDJWT::Error, 'decoys must be an Integer or a path-to-count Hash'
        end
      end

      def validate_decoy_count!(count)
        raise SDJWT::Error, 'decoy counts cannot be negative' if count.negative?

        count
      end

      def random_digest
        @hash_algorithm.digest(Disclosure.salt(@rng, @salt_bytes))
      end

      def validate_paths!
        if @paths.any? { |path| path.first == 'cnf' }
          raise SDJWT::Error, 'cnf must not be selectively disclosable'
        end
        @paths.each { |path| validate_value!(path, @original_payload) }
        sorted = @paths.sort_by(&:length)
        sorted.each_with_index do |path, index|
          prefixes = sorted[(index + 1)..-1].to_a.select { |candidate| candidate[0...path.length] == path }
          raise SDJWT::Error, 'Cannot disclose both a value and one of its descendants' unless prefixes.empty?
        end
      end

      def validate_options!
        unless @salt_bytes.is_a?(::Integer) && @salt_bytes >= 16
          raise SDJWT::Error, 'salt_bytes must be an Integer of at least 16'
        end
      end

      def validate_value!(path, value)
        raise SDJWT::Error, 'Disclosable paths must not be empty' if path.empty?

        begin
          path.each do |key|
            case value
            when ::Hash
              raise SDJWT::Error, "Unknown disclosable path: #{path.inspect}" unless value.key?(key)

              value = value[key]
            when ::Array
              index = Integer(key)
              raise SDJWT::Error, "Unknown disclosable path: #{path.inspect}" if index < 0 || index >= value.size

              value = value[index]
            else
              raise SDJWT::Error, "Unknown disclosable path: #{path.inspect}"
            end
          end
        rescue ArgumentError
          raise SDJWT::Error, "Unknown disclosable path: #{path.inspect}"
        end
      end

      def normalize_paths(paths)
        Array(paths).map do |path|
          Array(path).map do |component|
            component = component.to_s
            raise SDJWT::Error, 'Disclosable path components cannot be empty' if component.empty?

            component
          end
        end.uniq
      end

      def normalize(value)
        case value
        when ::Hash
          value.each_with_object({}) do |(key, child), object|
          normalized_key = key.to_s
          if RESERVED_KEYS.include?(normalized_key) || normalized_key == ARRAY_DIGEST_KEY
            raise SDJWT::Error, "#{normalized_key.inspect} is reserved by SD-JWT"
          end

          object[normalized_key] = normalize(child)
        end
        when ::Array
          value.map { |child| normalize(child) }
        else
          value
        end
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

      def canonical_jwk(key)
        return nil unless key

        if @original_payload.key?('cnf')
          raise SDJWT::Error, 'Do not provide both a cnf claim and holder_jwk'
        end

        jwk = case key
              when ::Hash then normalize(key)
              when JWT::JWK::KeyBase then key.members
              else
                created = JWT::JWK.create_from(key)
                raise SDJWT::Error, 'Key Binding cnf.jwk must be an asymmetric public key' unless created.respond_to?(:members)

                created.members
        end
        jwk = jwk.each_with_object({}) { |(jwk_key, value), normalized| normalized[jwk_key.to_s] = value }
        raise SDJWT::Error, 'Key Binding cnf.jwk must be an asymmetric public JWK' if jwk.key?('k')
        jwk.delete('kid')
        jwk
      end
    end
  end
end
