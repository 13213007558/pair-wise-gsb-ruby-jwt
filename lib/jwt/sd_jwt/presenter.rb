# frozen_string_literal: true

module JWT
  module SDJwt
    class Presenter
      Descriptor = Struct.new(:path, :disclosure, keyword_init: true)

      def initialize(sd_jwt, claims: nil, paths: nil, key_binding: nil)
        @parsed = Compact.parse(sd_jwt)
        requested = claims || paths || []
        @paths = (requested == :all ? :all : normalize_paths(requested))
        @key_binding = key_binding
      end

      def present
        disclosures_by_digest = map_disclosures(@parsed.disclosures)
        payload = issuer_payload
        descriptors = []
        collect_descriptors(payload, [], disclosures_by_digest, descriptors)

        unless @paths == :all
          @paths.each { |path| validate_path!(payload, path, disclosures_by_digest) }
        end

        selected = select_disclosures(descriptors)
        prefix = [@parsed.jwt, *selected.map(&:encoded), nil].join('~')
        @key_binding ? bind(prefix, payload) : prefix
      end

      private

      def map_disclosures(disclosures)
        disclosures.each_with_object({}) { |disclosure, memo| memo[disclosure.digest] = disclosure }
      end

      def issuer_payload
        JWT::JSON.parse(JWT::Base64.url_decode(EncodedToken.new(@parsed.jwt).encoded_payload))
      end

      def collect_descriptors(value, path, disclosures, descriptors)
        case value
        when Hash
          collect_hash_descriptors(value, path, disclosures, descriptors)
        when Array
          collect_array_descriptors(value, path, disclosures, descriptors)
        end
      end

      def collect_hash_descriptors(hash, path, disclosures, descriptors)
        raw_digests = hash[SD_CLAIM]
        return unless raw_digests.is_a?(Array)

        raw_digests.each do |digest|
          disclosure = disclosures[digest]
          next unless disclosure&.claim_name

          descriptor_path = path + [disclosure.claim_name]
          descriptors << Descriptor.new(path: descriptor_path, disclosure: disclosure)
          collect_descriptors(disclosure.value, descriptor_path, disclosures, descriptors)
        end

        hash.each do |key, child|
          next if key == SD_CLAIM || key == SD_ALGORITHM_CLAIM

          collect_descriptors(child, path + [key], disclosures, descriptors)
        end
      end

      def collect_array_descriptors(array, path, disclosures, descriptors)
        array.each_with_index do |child, index|
          descriptor_path = path + [index.to_s]
          if marker?(child)
            disclosure = disclosures[child[ARRAY_SD_MARKER]]
            next unless disclosure&.array_element?

            descriptors << Descriptor.new(path: descriptor_path, disclosure: disclosure)
            collect_descriptors(disclosure.value, descriptor_path, disclosures, descriptors)
          else
            collect_descriptors(child, descriptor_path, disclosures, descriptors)
          end
        end
      end

      def select_disclosures(descriptors)
        return descriptors.map(&:disclosure) if @paths == :all

        descriptors.select do |descriptor|
          @paths.any? do |requested|
            requested == descriptor.path ||
              descriptor.path == requested.first(descriptor.path.size) ||
              requested == descriptor.path.first(requested.size)
          end
        end.map(&:disclosure).uniq(&:encoded)
      end

      def validate_path!(payload, path, disclosures)
        unless path_exists?(payload, path, disclosures)
          raise ClaimNotFound, "Claim #{path.join('.')} is not available for disclosure"
        end
      end

      def path_exists?(value, path, disclosures)
        return true if path.empty?

        head, *rest = path
        case value
        when Hash
          disclosed_match?(value, head, rest, disclosures) || plain_match?(value, head, rest, disclosures)
        when Array
          array_match?(value, head, rest, disclosures)
        else
          false
        end
      end

      def disclosed_match?(hash, head, rest, disclosures)
        raw_digests = hash[SD_CLAIM]
        return false unless raw_digests.is_a?(Array)

        raw_digests.any? do |digest|
          disclosure = disclosures[digest]
          disclosure&.claim_name == head && path_exists?(disclosure.value, rest, disclosures)
        end
      end

      def plain_match?(hash, head, rest, disclosures)
        ![SD_CLAIM, SD_ALGORITHM_CLAIM].include?(head) &&
          hash.key?(head) && path_exists?(hash[head], rest, disclosures)
      end

      def array_match?(array, head, rest, disclosures)
        return false unless head =~ /\A[0-9]+\z/

        index = head.to_i
        return false if index >= array.size

        child = array[index]
        if marker?(child)
          disclosure = disclosures[child[ARRAY_SD_MARKER]]
          disclosure && path_exists?(disclosure.value, rest, disclosures)
        else
          path_exists?(child, rest, disclosures)
        end
      end

      def bind(prefix, payload)
        unless payload['cnf'].is_a?(Hash)
          raise KeyBindingError, 'Issuer JWT does not contain a cnf claim for key binding'
        end

        holder_key = @key_binding.fetch(:holder_key)
        kb_payload = {
          'aud' => @key_binding.fetch(:audience),
          'nonce' => @key_binding.fetch(:nonce),
          'iat' => @key_binding.fetch(:iat),
          'sd_hash' => SDJwt.sd_hash(prefix)
        }
        headers = { 'typ' => KEY_BINDING_TYPE }.merge(@key_binding[:headers] || {})
        kb_jwt = JWT.encode(kb_payload, holder_key, @key_binding[:algorithm] || 'ES256', headers)
        "#{prefix}#{kb_jwt}"
      end

      def marker?(value)
        value.is_a?(Hash) && value.size == 1 && value.key?(ARRAY_SD_MARKER)
      end

      def normalize_paths(paths)
        unless paths.is_a?(Array)
          raise ArgumentError, 'paths must be an Array'
        end

        paths.map { |path| path.is_a?(Array) ? path.map(&:to_s) : path.to_s.split('.') }
      end
    end
  end
end
