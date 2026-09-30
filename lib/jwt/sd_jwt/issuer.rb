# frozen_string_literal: true

module JWT
  module SDJwt
    class Issuer
      RESERVED_CLAIMS = [SD_CLAIM, SD_ALGORITHM_CLAIM].freeze
      private_constant(:RESERVED_CLAIMS)

      def initialize(payload:, signer:, disclosable_paths:, decoy_digests:, holder_public_key:, headers:)
        @payload = deep_copy(payload)
        @signer = signer
        @disclosable_paths = disclosable_paths.map { |path| normalize_path(path) }
        @decoy_digests = decoy_digests
        @holder_public_key = holder_public_key
        @headers = headers
        @disclosures = []
      end

      def issue
        validate_payload!(@payload)
        validate_decoy_digests!
        if @holder_public_key && @payload.key?('cnf')
          raise JWT::EncodeError, 'The cnf claim cannot be set by the issuer when holder binding is enabled'
        end
        apply_paths!(@payload, @disclosable_paths)
        transformed = transform(@payload, root: true)
        add_cnf!(transformed)
        transformed[SD_ALGORITHM_CLAIM] = HASH_ALGORITHM
        jwt = JWT.encode(transformed, @signer.fetch(:key), @signer.fetch(:algorithm), default_headers.merge(@signer[:headers] || {}).merge(@headers))
        [jwt, *@disclosures.map(&:encoded), nil].join('~')
      end

      private

      def validate_decoy_digests!
        unless @decoy_digests.is_a?(Integer) && @decoy_digests >= 0
          raise JWT::EncodeError, 'decoy_digests must be a non-negative Integer'
        end
      end

      def validate_payload!(value)
        case value
        when Disclosable
          validate_payload!(value.value)
        when Hash
          value.each do |key, child|
            raise JWT::EncodeError, "Reserved SD-JWT claim #{key} cannot be supplied by the issuer" if RESERVED_CLAIMS.include?(key)
            raise JWT::EncodeError, 'Reserved array marker cannot be used in an object' if key == ARRAY_SD_MARKER

            validate_payload!(child)
          end
        when Array
          value.each { |child| validate_payload!(child) }
        end
      end

      def apply_paths!(value, paths)
        if paths.any?(&:empty?)
          raise JWT::EncodeError, 'Cannot disclose a claim both wholly and partially' unless paths.size == 1

          return Disclosable.new(value)
        end

        grouped = paths.group_by(&:first)
        grouped.each do |head, child_paths|
          unless value.is_a?(Hash) && value.key?(head)
            raise ClaimNotFound, "Claim #{child_paths.first.join('.')} is not present in the issuer payload"
          end

          rest = child_paths.map { |path| path.drop(1) }
          value[head] = apply_path(value[head], rest)
        end
        value
      end

      def apply_path(value, paths)
        if paths.empty? || paths == [[]]
          raise JWT::EncodeError, 'Cannot disclose a claim both wholly and partially' if contains_disclosable?(value)

          Disclosable.new(value)
        elsif paths.any?(&:empty?)
          raise JWT::EncodeError, 'Cannot disclose a claim both wholly and partially'
        elsif value.is_a?(Hash)
          apply_paths!(value, paths)
        elsif value.is_a?(Array)
          grouped = paths.group_by(&:first)
          grouped.each do |head, child_paths|
            index = array_index(head, value)
            rest = child_paths.map { |path| path.drop(1) }
            value[index] = apply_path(value[index], rest)
          end
          value
        else
          raise ClaimNotFound, "Claim #{paths.first.join('.')} is not present in the issuer payload"
        end
      end

      def contains_disclosable?(value)
        value.is_a?(Disclosable) || value.is_a?(Hash) && value.any? { |_, child| contains_disclosable?(child) } ||
          value.is_a?(Array) && value.any? { |child| contains_disclosable?(child) }
      end

      def transform(value, root: false)
        case value
        when Hash
          transform_hash(value, root)
        when Array
          transform_array(value)
        else
          value
        end
      end

      def transform_hash(hash, root)
        result = {}
        sd = []

        hash.each do |key, value|
          if value.is_a?(Disclosable)
            transformed = transform(value.value)
            disclosure = Disclosure.create_property(key, transformed, value.salt || Disclosure.random_salt)
            @disclosures << disclosure
            sd << disclosure.digest
          else
            result[key] = transform(value)
          end
        end

        if root
          add_decoy_digests(sd)
        end

        result[SD_CLAIM] = sd.sort unless sd.empty?
        result
      end

      def add_decoy_digests(sd)
        @decoy_digests.times do
          sd << Base64.url_encode(SecureRandom.random_bytes(DIGEST_LENGTH))
        end
      end

      def transform_array(array)
        array.map do |value|
          if value.is_a?(Disclosable)
            transformed = transform(value.value)
            disclosure = Disclosure.create_array_element(transformed, value.salt || Disclosure.random_salt)
            @disclosures << disclosure
            { ARRAY_SD_MARKER => disclosure.digest }
          else
            transform(value)
          end
        end
      end

      def add_cnf!(payload)
        return unless @holder_public_key

        raise JWT::EncodeError, 'The cnf claim cannot be set by the issuer when holder binding is enabled' if payload.key?('cnf')

        payload['cnf'] = { 'jkt' => SDJwt.key_thumbprint(@holder_public_key) }
      end

      def default_headers
        { 'typ' => 'vc+sd-jwt' }
      end

      def deep_copy(value)
        case value
        when Disclosable then Disclosable.new(deep_copy(value.value), salt: value.salt)
        when Hash then value.each_with_object({}) { |(key, child), memo| memo[key.to_s] = deep_copy(child) }
        when Array then value.map { |child| deep_copy(child) }
        else value
        end
      end

      def normalize_path(path)
        return path.map(&:to_s) if path.is_a?(Array)

        path.to_s.split('.')
      end

      def array_index(key, array)
        unless key =~ /\A[0-9]+\z/
          raise ClaimNotFound, 'Array element claims must be disclosed by non-negative integer index'
        end

        index = key.to_i
        raise ClaimNotFound, 'Array element index is outside the array' if index >= array.size

        index
      end
    end
  end
end
