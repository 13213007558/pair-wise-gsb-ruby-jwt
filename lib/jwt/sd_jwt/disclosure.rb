# frozen_string_literal: true

require 'securerandom'

module JWT
  module SDJWT
    # One RFC 9901 disclosure. The original base64url-encoded form is the hash
    # input and is therefore retained verbatim.
    class Disclosure
      ATTRIBUTE = 2
      ARRAY_ELEMENT = 1
      MINIMUM_SALT_BYTES = 16

      attr_reader :encoded, :salt, :key, :value

      def self.create(key, value, salt:)
        array = key.nil? ? [salt, value] : [salt, key, value]
        encoded = JWT::Base64.url_encode(JWT::JSON.generate(array))
        new(encoded)
      end

      def self.salt(rng, bytes)
        JWT::Base64.url_encode(rng.bytes(bytes))
      end

      def initialize(encoded)
        @encoded = encoded
        unless encoded.is_a?(::String) && encoded.match?(/\A[A-Za-z0-9_-]+\z/)
          raise MalformedDisclosureError, 'Disclosure must be unpadded base64url'
        end

        raw = JWT::Base64.url_decode(encoded)
        array = JWT::JSON.parse(raw)

        unless valid_container?(array)
          raise MalformedDisclosureError,
                'Disclosure must be a non-empty salt plus claim or array element'
        end
        if array.first.bytesize < MINIMUM_SALT_BYTES
          raise MalformedDisclosureError, 'Disclosure salt must contain at least 128 bits'
        end

        @salt = array[0]
        assign_claim(array)
      rescue JWT::Base64DecodeError, ::JSON::ParserError
        raise MalformedDisclosureError,
              'Disclosure is not valid base64url-encoded JSON'
      end

      def attribute?
        @kind == ATTRIBUTE
      end

      def array_element?
        @kind == ARRAY_ELEMENT
      end

      def digest(hash_algorithm)
        hash_algorithm.digest(encoded)
      end

      private

      def valid_container?(array)
        array.is_a?(::Array) &&
          (array.size == 2 || array.size == 3) &&
          array.first.is_a?(::String) &&
          !array.first.empty?
      end

      def assign_claim(array)
        if array.size == 3
          assign_attribute(array)
        else
          @kind = ARRAY_ELEMENT
          @value = array[1]
        end
      end

      def assign_attribute(array)
        unless array[1].is_a?(::String) && !array[1].empty?
          raise MalformedDisclosureError,
                'Object disclosure claim name must be a non-empty string'
        end

        @kind = ATTRIBUTE
        @key = array[1]
        @value = array[2]
      end
    end
  end
end
