# frozen_string_literal: true

module JWT
  module SDJWT
    # Selects disclosures from an issued compact SD-JWT and creates presentations.
    class Selector
      ARRAY_DIGEST_KEY = ''

      def initialize(token)
        @issued_jwt, encoded_disclosures, key_binding_jwt = Compact.parse(token)
        raise MalformedTokenError, 'Cannot create a new presentation from a token already containing Key Binding' if key_binding_jwt

        @issuer_payload = decode_payload(@issued_jwt)
        @disclosures = encoded_disclosures.map { |encoded| [encoded, Disclosure.new(encoded)] }.to_h
        @digests = {}
        @disclosures.each_value { |disclosure| @digests[disclosure.digest(hash_algorithm)] = disclosure }
      end

      def disclose(paths = [])
        selected_paths = normalize_paths(paths)
        selected_paths.each { |path| validate_path!(path) }

        selected_encoded = []
        collect(@issuer_payload, [], selected_paths, selected_encoded)
        available_order = @disclosures.keys
        selected_encoded.sort_by { |encoded| available_order.index(encoded) }
      end

      def present(paths: [], key_binding: nil)
        encoded_disclosures = disclose(paths)
        kb_jwt = key_binding ? create_key_binding(encoded_disclosures, key_binding) : nil
        Compact.serialize(@issued_jwt, encoded_disclosures, kb_jwt)
      end

      private

      def hash_algorithm
        @hash_algorithm ||= HashAlgorithm.find(@issuer_payload['_sd_alg'])
      end

      def collect(value, path, selected_paths, selected_encoded)
        case value
        when ::Hash
          collect_object(value, path, selected_paths, selected_encoded)
        when ::Array
          collect_array(value, path, selected_paths, selected_encoded)
        end
      end

      def collect_object(object, path, selected_paths, selected_encoded) # rubocop:disable Metrics/MethodLength
        (object['_sd'] || []).each do |digest|
          disclosure = @digests[digest]
          next unless disclosure&.attribute?

          claim_path = path + [disclosure.key]
          next unless selected?(claim_path, selected_paths)

          append_disclosure(disclosure, selected_encoded)
          collect(disclosure.value, claim_path, selected_paths, selected_encoded)
        end

        object.each do |key, child|
          next if key == '_sd'

          child_path = path + [key]
          collect(child, child_path, selected_paths, selected_encoded) if descendant_selected?(child_path, selected_paths)
        end
      end

      def collect_array(array, path, selected_paths, selected_encoded)
        array.each_with_index do |child, index|
          child_path = path + [index.to_s]
          if array_marker?(child)
            disclosure = @digests[child[ARRAY_DIGEST_KEY]]
            next unless disclosure&.array_element? && selected?(child_path, selected_paths)

            append_disclosure(disclosure, selected_encoded)
            collect(disclosure.value, child_path, selected_paths, selected_encoded)
          else
            collect(child, child_path, selected_paths, selected_encoded) if descendant_selected?(child_path, selected_paths)
          end
        end
      end

      def append_disclosure(disclosure, selected_encoded)
        selected_encoded << disclosure.encoded unless selected_encoded.include?(disclosure.encoded)
      end

      def selected?(path, selected_paths)
        selected_paths.include?([]) || selected_paths.any? { |selected| path[0...selected.length] == selected }
      end

      def descendant_selected?(path, selected_paths)
        selected_paths.any? { |selected| selected[0...path.length] == path }
      end

      def validate_path!(path, value = @issuer_payload)
        return if path.empty?

        path.each do |key|
          value = resolve_value(value, key, path)
        end
      end

      def resolve_value(value, key, full_path)
        case value
        when ::Hash
          return value[key] if value.key?(key) && key != '_sd'

          resolve_disclosed_hash_value(value, key, full_path)
        when ::Array
          resolve_array_value(value, Integer(key), full_path)
        else
          raise SDJWT::Error, "Unknown disclosure path: #{full_path.inspect}"
        end
      rescue ArgumentError
        raise SDJWT::Error, "Unknown disclosure path: #{full_path.inspect}"
      end

      def resolve_disclosed_hash_value(object, key, full_path)
        (object['_sd'] || []).each do |digest|
          disclosure = @digests[digest]
          next unless disclosure&.attribute? && disclosure.key == key

          return disclosure.value
        end
        raise SDJWT::Error, "Unknown disclosure path: #{full_path.inspect}"
      end

      def resolve_array_value(array, index, full_path)
        raise SDJWT::Error, "Unknown disclosure path: #{full_path.inspect}" if index < 0 || index >= array.size

        child = array[index]
        return @digests.fetch(child[ARRAY_DIGEST_KEY]).value if array_marker?(child)

        child
      rescue KeyError
        raise SDJWT::Error, "Unknown disclosure path: #{full_path.inspect}"
      end

      def array_marker?(value)
        value.is_a?(::Hash) && value.size == 1 && value.key?(ARRAY_DIGEST_KEY)
      end

      def normalize_paths(paths)
        return [[]] if paths.nil? || paths == :all
        return [] if Array(paths).empty?

        Array(paths).map do |path|
          Array(path).map(&:to_s).tap { |components| components.each { |component| raise SDJWT::Error, 'Path components cannot be empty' if component.empty? } }
        end.uniq
      end

      def decode_payload(jwt)
        encoded_payload = jwt.split('.', 3)[1]
        JWT::JSON.parse(JWT::Base64.url_decode(encoded_payload)).tap do |payload|
          raise MalformedTokenError, 'Issuer JWT payload must be an object' unless payload.is_a?(::Hash)
        end
      rescue JWT::Base64DecodeError, ::JSON::ParserError
        raise MalformedTokenError, 'Issuer JWT payload is not valid base64url-encoded JSON'
      end

      def create_key_binding(disclosures, options)
        KeyBinding.create(
          presentation_input: Compact.presentation_input(@issued_jwt, disclosures),
          hash_algorithm: hash_algorithm,
          **options
        ).jwt
      end
    end
  end
end
