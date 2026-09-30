# frozen_string_literal: true

module JWT
  module JWS
    # Verification outcome for one signature member of a JWS JSON Serialization.
    class SignatureResult
      # @return [Integer] zero based position of the signature in the serialization.
      attr_reader :index

      # @return [String, nil] the key id of the signature.
      attr_reader :kid

      # @return [Hash] the merged protected and unprotected headers.
      attr_reader :header

      # @return [String, nil] the reason the signature could not be verified.
      attr_reader :error

      # @api private
      def initialize(index:, header:, valid:, error: nil, identity: nil)
        @index = index
        @header = header
        @kid = header['kid']
        @valid = valid
        @error = error
        @identity = identity
      end

      # @return [Boolean] whether the signature was successfully verified.
      def valid?
        @valid
      end

      # @return identity of the independent signer that produced the signature.
      # @api private
      attr_reader :identity
    end

    # Outcome of verifying a JWS JSON Serialization against a caller policy.
    #
    # The payload ({#claims}/{#payload}) is only available when {#verified?}
    # is true. Use {#unverified_payload} if the raw payload is needed without
    # trusting it.
    class VerificationResult
      # @return [Array<JWT::JWS::SignatureResult>] the per-signature results.
      attr_reader :signatures

      # @return [String, nil] the overall reason the policy was not satisfied.
      attr_reader :error

      # @api private
      def initialize(encoded_payload:, signatures:, verified:, error: nil)
        @encoded_payload = encoded_payload
        @signatures = signatures
        @verified = verified
        @error = error
      end

      # @return [Boolean] whether the verification policy was satisfied and the claims are valid.
      def verified?
        @verified
      end

      alias valid? verified?

      # The verified claims of the payload.
      #
      # @return [Hash] the decoded payload claims.
      # @raise [JWT::TokenError] when the verification policy was not satisfied.
      def payload
        raise ::JWT::TokenError, error || 'JWS verification policy was not satisfied' unless verified?

        unverified_payload
      end

      alias claims payload

      # @return [Hash] the decoded payload without any verification guarantee.
      def unverified_payload
        return {} unless @encoded_payload

        @unverified_payload ||= ::JWT::JSON.parse(::JWT::Base64.url_decode(@encoded_payload))
      end

      # @return [Hash] the headers of the first successfully verified signature.
      # @raise [JWT::TokenError] when no signature was verified.
      def header
        verified_header = signatures.find(&:valid?)&.header
        return verified_header if verified_header

        raise ::JWT::TokenError, 'No verified signature available'
      end
    end
  end
end
