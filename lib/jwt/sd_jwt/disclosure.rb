# frozen_string_literal: true

require_relative 'hasher'

module JWT
  module SDJWT
    # Represents a Disclosure as defined by RFC 9901 section 5.
    #
    # A disclosure is the base64url encoded array `[salt, claim_name, claim_value]`
    # (object properties) or `[salt, element]` (array elements).
    class Disclosure
      # @return [String] the base64url encoded disclosure, as carried in an SD-JWT.
      attr_reader :encoded

      # Creates a disclosure for an object member.
      #
      # @param claim_name [String, Symbol] the name of the disclosed claim.
      # @param claim_value [Object] the value of the disclosed claim.
      # @param salt [String, nil] the salt to use. A random one is generated when omitted.
      # @param path [Array, nil] the path of the claim in the issuer payload.
      # @return [Disclosure]
      def self.property(claim_name, claim_value, salt = nil, path: nil)
        new([salt || Hasher.random_salt, claim_name.to_s, claim_value], nil, path: path)
      end

      # Creates a disclosure for an array element.
      #
      # @param element [Object] the disclosed array element.
      # @param salt [String, nil] the salt to use. A random one is generated when omitted.
      # @param path [Array, nil] the path of the element in the issuer payload.
      # @return [Disclosure]
      def self.array_element(element, salt = nil, path: nil)
        new([salt || Hasher.random_salt, element], nil, path: path)
      end

      # Decodes and validates a base64url encoded disclosure.
      #
      # @param encoded [String] the encoded disclosure.
      # @return [Disclosure]
      # @raise [JWT::SDJWTMalformedError] if the disclosure is not valid.
      def self.decode(encoded)
        raise ::JWT::SDJWTMalformedError, 'Disclosure must be a String' unless encoded.is_a?(::String)
        raise ::JWT::SDJWTMalformedError, 'Disclosure must not be empty' if encoded.empty?

        json = begin
          ::JWT::Base64.url_decode(encoded)
        rescue ::JWT::Base64DecodeError
          raise ::JWT::SDJWTMalformedError, 'Disclosure is not valid base64url'
        end

        array = begin
          ::JWT::JSON.parse(json)
        rescue ::JSON::ParserError
          raise ::JWT::SDJWTMalformedError, 'Disclosure does not contain valid JSON'
        end

        new(array, encoded)
      end

      # @return [Array, nil] the path of this disclosure within the issuer payload,
      #   populated for disclosures created by the {Issuer}.
      attr_reader :path

      # @return [String] the salt of the disclosure.
      def salt
        array[0]
      end

      # @return [String, nil] the disclosed claim name for object property disclosures.
      def key
        property? ? array[1] : nil
      end

      # @return [Object] the disclosed value (claim value or array element).
      def value
        property? ? array[2] : array[1]
      end

      # @return [Boolean] whether the disclosure carries an object property.
      def property?
        array.length == 3
      end

      # @return [Boolean] whether the disclosure carries an array element.
      def array_element?
        array.length == 2
      end

      # Returns the base64url encoded digest that references this disclosure.
      #
      # @param algorithm [String] the hash algorithm declared by the SD-JWT.
      # @return [String]
      def digest(algorithm = 'sha-256')
        @digest ||= {}
        @digest[algorithm] ||= Hasher.digest(encoded, algorithm)
      end

      # @return [String] the encoded disclosure.
      def to_s
        encoded
      end

      # Two disclosures are considered equal when their encoded form is equal.
      #
      # @return [Boolean]
      def ==(other)
        other.is_a?(self.class) && encoded == other.encoded
      end
      alias eql? ==

      # @return [Integer]
      def hash
        encoded.hash
      end

      private

      attr_reader :array

      def initialize(array, encoded = nil, path: nil)
        validate!(array)
        @array = array
        @encoded = encoded || ::JWT::Base64.url_encode(::JWT::JSON.generate(array))
        @path = path
      end

      def validate!(array)
        unless array.is_a?(::Array) && (array.length == 2 || array.length == 3)
          raise ::JWT::SDJWTMalformedError, 'Disclosure must be a JSON array with 2 or 3 elements'
        end

        unless array[0].is_a?(::String) && !array[0].empty?
          raise ::JWT::SDJWTMalformedError, 'Disclosure salt must be a non-empty string'
        end

        if array.length == 2
          # [salt, element]: the element can be any JSON value, no further check.
          return
        end

        unless array[1].is_a?(::String) && !array[1].empty?
          raise ::JWT::SDJWTMalformedError, 'Disclosure claim name must be a non-empty string'
        end

        if %w[_sd ... _sd_alg].include?(array[1])
          raise ::JWT::SDJWTMalformedError, "Claim name '#{array[1]}' is reserved by the SD-JWT specification"
        end
      end
    end
  end
end
