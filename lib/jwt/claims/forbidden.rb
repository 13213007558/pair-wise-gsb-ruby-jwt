# frozen_string_literal: true

module JWT
  module Claims
    # The Forbidden class is responsible for validating that claims which must not be
    # present in a token intended for a specific purpose are absent from the payload.
    class Forbidden
      # Initializes a new Forbidden instance.
      #
      # @param forbidden_claims [Array<String>] the list of claims that must not be present.
      def initialize(forbidden_claims:)
        @forbidden_claims = Array(forbidden_claims).map(&:to_s)
      end

      # Verifies that none of the forbidden claims are present in the JWT payload.
      #
      # @param context [Object] the context containing the JWT payload.
      # @param _args [Hash] additional arguments (not used).
      # @raise [JWT::ForbiddenClaimError] if any forbidden claim is present.
      # @return [nil]
      def verify!(context:, **_args)
        return unless context.payload.is_a?(Hash)

        present = forbidden_claims.select { |claim| context.payload.key?(claim) }
        return if present.empty?

        raise JWT::ForbiddenClaimError, "Forbidden claim(s) present: #{present.join(', ')}"
      end

      private

      attr_reader :forbidden_claims
    end
  end
end
