# frozen_string_literal: true

require 'openssl'

module JWT
  module SDJWT
    # A Disclosure carries the salt, claim name (object members only) and the
    # disclosed value that together hash to one of the digests ("sd hash")
    # embedded in the issuer-signed JWT.
    #
    # An object member disclosure is serialized as [salt, claim_name, value],
    # an array element disclosure as [salt, value].
    #
    # @see https://www.rfc-editor.org/rfc/rfc9901#section-5 RFC 9901 section 5
    class Disclosure
      # @return [String] the random salt of the disclosure.
      attr_reader :salt

      # @return [String, nil] the disclosed claim name, or nil for array element disclosures.
      attr_reader :claim_name

      # @return [Object] the disclosed value.
      attr_reader :value

      # @param encoded [String] the base64url-encoded disclosure.
      # @return [Disclosure] the parsed disclosure.
      # @raise [JWT::SDJWTFormatError] if the disclosure cannot be parsed.
      def self.from_encoded(encoded)
        raise JWT::SDJWTFormatError, 'Disclosure must be a non empty String' unless encoded.is_a?(::String) && !encoded.empty?

        json = begin
          ::JWT::Base64.url_decode(encoded)
        rescue JWT::Base64DecodeError
          raise JWT::SDJWTFormatError, 'Disclosure is not valid base64url encoded'
        end

        array = begin
          JWT::JSON.parse(json)
        rescue ::JSON::ParserError
          raise JWT::SDJWTFormatError, 'Disclosure does not contain valid JSON'
        end

        unless array.is_a?(::Array) && (array.size == 2 || array.size == 3)
          raise JWT::SDJWTFormatError, 'Disclosure must be a JSON array with two or three elements'
        end

        salt, claim_name, value = array.size == 3 ? array : [array[0], nil, array[1]]

        unless salt.is_a?(::String) && !salt.empty?
          raise JWT::SDJWTFormatError, 'Disclosure salt must be a non empty String'
        end

        if array.size == 3 && !(claim_name.is_a?(::String) && !claim_name.empty?)
          raise JWT::SDJWTFormatError, 'Disclosure claim name must be a non empty String'
        end

        disclosure = new(salt: salt, claim_name: claim_name, value: value)
        disclosure.instance_variable_set(:@encoded, encoded)
        disclosure
      end

      # @param salt [String] the random salt.
      # @param claim_name [String, nil] the claim name for object member disclosures.
      # @param value [Object] the disclosed value.
      def initialize(salt:, value:, claim_name: nil)
        @salt = salt
        @claim_name = claim_name
        @value = value
        @encoded = nil
      end

      # @return [Array] the disclosure data as it is serialized and hashed.
      def to_a
        claim_name ? [salt, claim_name, value] : [salt, value]
      end

      # @return [String] the base64url-encoded disclosure.
      def encoded
        @encoded ||= ::JWT::Base64.url_encode(JWT::JSON.generate(to_a))
      end

      # @return [String] the hex encoded digest over the disclosure.
      def digest(algorithm = DEFAULT_SD_ALG)
        Digestable.new(algorithm).digest(encoded)
      end

      # @return [String]
      def to_s
        encoded
      end
    end
  end
end
