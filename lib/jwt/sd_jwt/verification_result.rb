# frozen_string_literal: true

module JWT
  module SDJWT
    # The result of a successful SD-JWT verification. Only claims actually
    # disclosed by the holder are present in +claims+.
    class VerificationResult
      # @return [Hash] the recursively disclosed claims.
      attr_reader :claims

      # @return [Hash] the header of the issuer signed JWT.
      attr_reader :header

      # @return [Array<Disclosure>] the disclosures that were presented and used.
      attr_reader :disclosures

      # @return [Hash, nil] the payload of the Key Binding JWT, if one was present.
      attr_reader :key_binding

      # @api private
      def initialize(claims:, header:, disclosures:, key_binding: nil)
        @claims = claims
        @header = header
        @disclosures = disclosures
        @key_binding = key_binding
      end

      # @return [Hash] the disclosed claims.
      def to_h
        claims
      end
    end
  end
end
