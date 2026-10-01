# frozen_string_literal: true

require 'securerandom'

module JWT
  module SDJWT
    # Creates an issuer signed SD-JWT (RFC 9901 section 4 / 5).
    #
    # Claims named in +disclosable+ are replaced by digests and their values are
    # moved into separate Disclosure objects. Nested object members and array
    # elements are supported through dot/bracket paths, for example:
    #
    #   disclosable: ['name', 'address.street', 'nationalities[0]']
    #
    # The signing algorithm and key reuse the standard JWT interfaces
    # (+JWT::Token#sign!+), so every supported JWA and key type (String,
    # OpenSSL key, JWT::JWK) works unchanged.
    class Issuer
      # Claim names controlled by the SD-JWT specification that must not appear
      # in the original claims.
      RESERVED_CLAIM_NAMES = %w[_sd _sd_alg ...].freeze

      # @param claims [Hash] the verifiable claims of the credential.
      # @param key [String, OpenSSL::PKey::PKey, JWT::JWK::KeyBase] the signing key.
      # @param algorithm [String, Object] the signing algorithm, defaults to HS256.
      # @param disclosable [Array<String>] paths of claims that are made selectively disclosable.
      # @param headers [Hash] additional headers for the issuer JWT (+typ+ defaults to +sd-jwt+).
      # @param holder_jwk [Hash, JWT::JWK::KeyBase] public key of the holder, embedded as +cnf.jwk+.
      # @param salt_provider [#call] callable returning a salt String, defaults to 128 bit random salts.
      def initialize(claims:, key:, algorithm: 'HS256', disclosable: [], headers: {}, holder_jwk: nil, salt_provider: nil)
        @claims = claims
        @key = key
        @algorithm = algorithm
        @headers = headers
        @holder_jwk = holder_jwk
        @salt_provider = salt_provider || default_salt_provider

        @disclosable_paths = parse_paths(disclosable)
        @disclosures = []
        @used_paths = []
      end

      # @return [CompoundSdJwt] the issued SD-JWT containing all disclosures.
      def issue
        raise JWT::SDJWTInvalidPayload, 'Claims must be a Hash' unless @claims.is_a?(::Hash)

        @claims = deep_dup(@claims)

        ensure_no_reserved_names!(@claims, [])

        transformed = transform_hash(@claims, [])

        missing_paths = @disclosable_paths.reject { |path| @used_paths.include?(path) }
        unless missing_paths.empty?
          raise JWT::SDJWTInvalidPayload, "Disclosable path not found in claims: #{missing_paths.map { |p| path_to_s(p) }.join(', ')}"
        end

        payload = transformed
        payload['_sd_alg'] = DEFAULT_SD_ALG unless @disclosures.empty?
        inject_holder_jwk!(payload)

        token = ::JWT::Token.new(payload: payload, header: default_headers.merge(@headers))
        token.verify_claims!(:numeric)
        token.sign!(algorithm: @algorithm, key: @key)

        CompoundSdJwt.new(issuer_jwt: token.jwt, disclosures: @disclosures)
      end

      private

      def default_salt_provider
        -> { ::SecureRandom.urlsafe_base64(16) }
      end

      def default_headers
        { 'typ' => 'sd-jwt' }
      end

      def inject_holder_jwk!(payload)
        return unless @holder_jwk

        if payload.key?('cnf')
          raise JWT::SDJWTInvalidPayload, 'Claims must not contain a "cnf" member when holder_jwk is given'
        end

        jwk = @holder_jwk.is_a?(::Hash) ? @holder_jwk : normalize_jwk(@holder_jwk)
        payload['cnf'] = { 'jwk' => jwk }
      end

      # JWK#export returns symbol keys; go through JSON once so the cnf claim is
      # a plain string keyed Hash just like any other claim.
      def normalize_jwk(jwk)
        JWT::JSON.parse(JWT::JSON.generate(jwk.export))
      end

      def next_salt
        salt = @salt_provider.call
        unless salt.is_a?(::String) && !salt.empty?
          raise JWT::SDJWTInvalidPayload, 'Salt provider must return a non empty String'
        end

        salt
      end

      def transform_hash(hash, current_path)
        result = {}
        sd_digests = []

        hash.each do |raw_key, value|
          key = raw_key.to_s
          child_path = current_path + [key]

          if @disclosable_paths.include?(child_path)
            @used_paths << child_path
            disclosure = Disclosure.new(salt: next_salt, claim_name: key, value: deep_dup(value))
            @disclosures << disclosure
            sd_digests << disclosure.digest
          else
            result[key] = transform_value(value, child_path)
          end
        end

        result = { '_sd' => sd_digests }.merge(result) unless sd_digests.empty?
        result
      end

      def transform_array(array, current_path)
        array.map.with_index do |value, index|
          child_path = current_path + [index]

          if @disclosable_paths.include?(child_path)
            @used_paths << child_path
            disclosure = Disclosure.new(salt: next_salt, value: deep_dup(value))
            @disclosures << disclosure
            { '...' => disclosure.digest }
          else
            transform_value(value, child_path)
          end
        end
      end

      def transform_value(value, current_path)
        case value
        when ::Hash
          transform_hash(value, current_path)
        when ::Array
          transform_array(value, current_path)
        else
          value
        end
      end

      def ensure_no_reserved_names!(value, current_path)
        case value
        when ::Hash
          value.each_key do |raw_key|
            key = raw_key.to_s
            raise JWT::SDJWTInvalidPayload, "Claim name #{key.inspect} is reserved by RFC 9901" if RESERVED_CLAIM_NAMES.include?(key)

            ensure_no_reserved_names!(value[raw_key], current_path + [key])
          end
        when ::Array
          value.each_with_index do |element, index|
            if element.is_a?(::Hash) && (element.key?('...') || element.key?(:'...'))
              raise JWT::SDJWTInvalidPayload, 'Claim name "..." is reserved by RFC 9901'
            end

            ensure_no_reserved_names!(element, current_path + [index])
          end
        end
      end

      def deep_dup(value)
        case value
        when ::Hash
          value.transform_keys(&:to_s).transform_values { |v| deep_dup(v) }
        when ::Array
          value.map { |v| deep_dup(v) }
        else
          value
        end
      end

      def parse_paths(paths)
        list = Array(paths).map { |path| self.class.parse_path(path) }

        list.each do |path|
          path.each do |component|
            next unless component.is_a?(::String) && RESERVED_CLAIM_NAMES.include?(component)

            raise JWT::SDJWTInvalidPayload, "Claim name #{component.inspect} is reserved by RFC 9901"
          end
        end

        if list.length != list.uniq.length
          raise JWT::SDJWTInvalidPayload, 'Disclosable paths must be unique'
        end

        # A disclosable claim cannot at the same time have disclosable children.
        list.permutation(2).each do |(outer, inner)|
          next if outer == inner

          if inner[0, outer.length] == outer
            raise JWT::SDJWTInvalidPayload,
                  "Path #{path_to_s(inner)} is nested inside disclosable path #{path_to_s(outer)}"
          end
        end

        list
      end

      # Parses paths like +address.street+ or +nationalities[0]+ into an array
      # of String keys and Integer array indexes.
      def self.parse_path(path)
        unless path.is_a?(::String) && !path.empty?
          raise JWT::SDJWTInvalidPayload, 'Disclosable paths must be non empty Strings'
        end

        components = []
        index = 0

        while index < path.length
          case path[index]
          when '.'
            index += 1
            start = index
            index += 1 while index < path.length && path[index] != '.' && path[index] != '['
            raise JWT::SDJWTInvalidPayload, "Invalid disclosable path: #{path}" if index == start

            components << path[start...index]
          when '['
            closing = path.index(']', index)
            raise JWT::SDJWTInvalidPayload, "Invalid disclosable path: #{path}" unless closing

            number = path[(index + 1)...closing]
            unless /\A\d+\z/.match?(number)
              raise JWT::SDJWTInvalidPayload, "Invalid array index in disclosable path: #{path}"
            end

            components << number.to_i
            index = closing + 1
          else
            start = index
            index += 1 while index < path.length && path[index] != '.' && path[index] != '['
            components << path[start...index]
          end
        end

        raise JWT::SDJWTInvalidPayload, "Invalid disclosable path: #{path}" if components.empty?

        components
      end

      def path_to_s(path)
        path.map.with_index do |component, idx|
          if component.is_a?(::Integer)
            "[#{component}]"
          elsif idx.zero?
            component
          else
            ".#{component}"
          end
        end.join
      end
    end
  end
end
