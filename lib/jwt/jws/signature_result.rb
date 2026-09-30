# frozen_string_literal: true

module JWT
  module JWS
    # Reports the verification outcome of a single JWS signature.
    class SignatureResult
      # @return [JWT::JWS::Signature] the verified signature.
      # @return [Boolean] whether the signature is valid.
      # @return [Exception, nil] the error raised while verifying the signature.
      # @return [Object, nil] the key that verified the signature.
      attr_reader :signature, :error, :key

      def initialize(signature:, error: nil, key: nil)
        @signature = signature
        @error     = error
        @key       = key
      end

      # @return [Boolean] whether the signature was verified successfully.
      def valid?
        error.nil?
      end

      # @return [Hash] the merged protected and unprotected headers of the signature.
      def header
        signature.header
      rescue ::JWT::Error
        {}
      end

      # @return [String, nil] the stable identity of the key that verified the signature.
      def key_identity
        key && KeyIdentity.of(key)
      end
    end
  end
end
