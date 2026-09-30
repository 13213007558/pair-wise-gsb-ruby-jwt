# frozen_string_literal: true

module JWT
  module JWS
    # Reports the outcome of verifying a JWS JSON Serialization against a
    # caller provided policy.
    class VerificationResult
      # @return [Object] the unverified decoded payload.
      # @return [Array<JWT::JWS::SignatureResult>] the per-signature results.
      # @return [JWT::JWS::Policy] the policy the result was evaluated against.
      # @return [Exception, nil] the claim verification error.
      attr_reader :payload, :signature_results, :policy, :claims_error

      def initialize(payload:, signature_results:, policy:, claims_error: nil)
        @payload           = payload
        @signature_results = signature_results
        @policy            = policy
        @claims_error      = claims_error
      end

      # @return [Boolean] whether both the signature policy and the claims are satisfied.
      def verified?
        policy_satisfied? && claims_error.nil?
      end

      # @return [Boolean] whether enough distinct signers produced valid signatures.
      def policy_satisfied?
        policy.satisfied?(signature_results)
      end

      # @return [Object] the payload, but only when the whole token is verified.
      # @raise [JWT::VerificationError] if the signature policy is not satisfied.
      # @raise [JWT::ClaimValidationError] if the claims are invalid.
      def verified_payload
        unless policy_satisfied?
          raise ::JWT::VerificationError, "JWS signature policy not satisfied: #{failure_summary}"
        end

        raise claims_error if claims_error

        payload
      end

      private

      def failure_summary
        failed = signature_results.reject(&:valid?)
        messages = failed.map.with_index(1) { |result, index| "##{index} #{result.error.message}" }
        extra = policy.description(signature_results)
        (messages + [extra]).join('; ')
      end
    end
  end
end
