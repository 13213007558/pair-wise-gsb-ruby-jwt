# frozen_string_literal: true

require_relative 'constants'
require_relative 'disclosure'

module JWT
  module SDJWT
    # A parsed or assembled SD-JWT presentation, i.e. the combined
    # serialization of an issuer JWT, zero or more disclosures and an optional
    # Key Binding JWT (RFC 9901 section 4).
    class Presentation
      # @return [String] the issuer JWT.
      attr_reader :jwt

      # @return [Array<Disclosure>] the disclosures carried by the presentation.
      attr_reader :disclosures

      # @return [String, nil] the serialized Key Binding JWT.
      attr_accessor :key_binding_jwt

      # Parses a combined SD-JWT serialization.
      #
      # Both the issuer form ending in a trailing `~` separator and the
      # presentation form ending in a Key Binding JWT are accepted.
      #
      # @param serialized [String] the `~` separated serialization.
      # @return [Presentation]
      # @raise [JWT::SDJWTMalformedError] if the serialization is malformed.
      def self.parse(serialized)
        raise ::JWT::SDJWTMalformedError, 'SD-JWT must be a String' unless serialized.is_a?(::String)

        parts = serialized.split(SEPARATOR, -1)
        raise ::JWT::SDJWTMalformedError, 'SD-JWT is empty' if parts.empty?

        jwt = parts[0]
        raise ::JWT::SDJWTMalformedError, 'SD-JWT does not contain a valid issuer JWT' unless jwt.count('.') == 2

        key_binding_jwt = nil
        tail = parts[-1]

        if parts.length > 1
          if tail == ''
            # Issuer-SD-JWT form: trailing separator, no Key Binding JWT.
            parts.pop
          elsif tail.count('.') == 2
            key_binding_jwt = parts.pop
          end
        end

        # A presentation without a Key Binding JWT has no trailing separator.
        encoded_disclosures = parts[1..] || []
        if encoded_disclosures.any? { |entry| entry.empty? }
          raise ::JWT::SDJWTMalformedError, 'Empty disclosure encountered in SD-JWT'
        end

        new(jwt, encoded_disclosures.map { |entry| Disclosure.decode(entry) }, key_binding_jwt)
      end

      # @param jwt [String] the issuer JWT.
      # @param disclosures [Array<Disclosure, String>] the disclosures to present.
      # @param key_binding_jwt [String, JWT::Token, nil] the Key Binding JWT.
      def initialize(jwt, disclosures = [], key_binding_jwt = nil)
        @jwt = jwt
        @disclosures = disclosures.map { |entry| entry.is_a?(Disclosure) ? entry : Disclosure.decode(entry) }
        @key_binding_jwt = key_binding_jwt.is_a?(::JWT::Token) ? key_binding_jwt.jwt : key_binding_jwt
      end

      # Adds a disclosure to the presentation.
      #
      # @param disclosure [Disclosure, String] the disclosure to carry.
      # @return [Presentation] self.
      def add(disclosure)
        disclosure = disclosure.is_a?(Disclosure) ? disclosure : Disclosure.decode(disclosure)
        @disclosures << disclosure unless @disclosures.include?(disclosure)
        self
      end
      alias << add

      # @return [String] the combined serialization. Presentations never have a
      #   trailing separator (the KB-JWT position is simply absent).
      def to_s
        parts = [jwt, *disclosures.map(&:encoded)]
        parts << key_binding_jwt.to_s if key_binding_jwt
        parts.join(SEPARATOR)
      end
      alias serialized to_s
    end
  end
end
