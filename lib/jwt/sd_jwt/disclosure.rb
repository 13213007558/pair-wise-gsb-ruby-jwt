# frozen_string_literal: true

module JWT
  module SDJwt
    class Disclosure
      attr_reader :encoded, :salt, :claim_name, :value

      def self.create(claim_name, value, salt = random_salt)
        create_property(claim_name, value, salt)
      end

      def self.create_property(claim_name, value, salt = random_salt)
        encoded = Base64.url_encode(
          JWT::JSON.generate([salt, claim_name, value])
        )
        new(encoded)
      end

      def self.create_array_element(value, salt = random_salt)
        encoded = Base64.url_encode(
          JWT::JSON.generate([salt, value])
        )
        new(encoded)
      end

      def self.parse(encoded)
        new(encoded)
      end

      def initialize(encoded)
        @encoded = encoded
        decoded = JWT::JSON.parse(Base64.url_decode(encoded))

        unless decoded.is_a?(Array) && (decoded.size == 2 || decoded.size == 3) && decoded.first.is_a?(String)
          raise MalformedTokenError, 'Disclosure must be a JSON array with a string salt'
        end

        @salt = decoded[0]
        if decoded.size == 3
          raise MalformedTokenError, 'Disclosure claim name must be a string' unless decoded[1].is_a?(String)

          @claim_name = decoded[1]
          @value = decoded[2]
        else
          @value = decoded[1]
        end
      rescue ::JSON::ParserError, ArgumentError
        raise MalformedTokenError, 'Disclosure must be valid Base64url-encoded JSON'
      end

      def array_element?
        claim_name.nil?
      end

      def digest
        SDJwt.digest(encoded)
      end

      def self.random_salt
        Base64.url_encode(SecureRandom.random_bytes(16))
      end
    end
  end
end
