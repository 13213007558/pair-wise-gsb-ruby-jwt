# frozen_string_literal: true

module JWT
  module SDJWT
    # A serialized SD-JWT as defined in RFC 9901 section 4:
    #
    #   <Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~<KB-JWT>
    #
    # The Key Binding JWT is optional.
    class CompoundSdJwt
      DISCLOSURE_SEPARATOR = '~'

      # @param serialized [String] the serialized combined SD-JWT.
      # @return [CompoundSdJwt] the parsed SD-JWT.
      # @raise [JWT::SDJWTFormatError] if the serialization is invalid.
      def self.parse(serialized)
        unless serialized.is_a?(::String) && !serialized.empty?
          raise JWT::SDJWTFormatError, 'SD-JWT must be a non empty String'
        end

        raise JWT::SDJWTFormatError, 'SD-JWT must use "~" to separate its parts' unless serialized.include?(DISCLOSURE_SEPARATOR)

        # A trailing "~" separates the disclosures from the (possibly missing)
        # KB JWT.
        parts = serialized.split(DISCLOSURE_SEPARATOR, -1)
        parts.pop if parts.last == '' # trailing "~" (required before a KB JWT, or end of the serialization)
        issuer_jwt = parts.shift

        raise JWT::SDJWTFormatError, 'SD-JWT issuer JWT must not be empty' if issuer_jwt.nil? || issuer_jwt.empty?
        raise JWT::SDJWTFormatError, 'SD-JWT issuer JWT must contain three segments' unless issuer_jwt.count('.') == 2

        kb_jwt = nil
        last = parts.last
        if last && last.count('.') == 2
          # The final segment is a Key Binding JWT (it has three JWT segments).
          kb_jwt = parts.pop
        end

        unless parts.all? { |part| part.is_a?(::String) && !part.empty? }
          raise JWT::SDJWTFormatError, 'Disclosures must not be empty'
        end

        disclosures = parts.map { |part| Disclosure.from_encoded(part) }

        new(issuer_jwt: issuer_jwt, disclosures: disclosures, kb_jwt: kb_jwt)
      end

      # @param issuer_jwt [String] the issuer signed JWT.
      # @param disclosures [Array<Disclosure>] the disclosures shared with the verifier.
      # @param kb_jwt [String, nil] the optional Key Binding JWT.
      def initialize(issuer_jwt:, disclosures: [], kb_jwt: nil)
        @issuer_jwt = issuer_jwt
        @disclosures = disclosures
        @kb_jwt = kb_jwt
      end

      # @return [String] the issuer signed JWT.
      attr_reader :issuer_jwt

      # @return [Array<Disclosure>] the disclosures presented to the verifier.
      attr_accessor :disclosures

      # @return [String, nil] the Key Binding JWT.
      attr_accessor :kb_jwt

      # @return [EncodedToken] the decoded issuer JWT, its signature is not verified.
      def encoded_token
        @encoded_token ||= ::JWT::EncodedToken.new(issuer_jwt)
      end

      # @return [Hash] the unverified payload of the issuer JWT.
      def unverified_payload
        encoded_token.unverified_payload
      end

      # @return [String] the serialization, terminated with "~".
      def to_s
        parts = [issuer_jwt, *disclosures.map(&:encoded)]
        parts << kb_jwt.to_s if kb_jwt
        parts.join(DISCLOSURE_SEPARATOR) + DISCLOSURE_SEPARATOR
      end
    end
  end
end
