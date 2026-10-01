# frozen_string_literal: true

module JWT
  module Claims
    # The NotBefore class is responsible for validating the 'nbf' (Not Before) claim in a JWT token.
    class NotBefore
      # Initializes a new NotBefore instance.
      #
      # @param leeway [Integer] the amount of leeway (in seconds) to allow when validating the 'nbf' claim. Defaults to 0.
      # @param clock [#call] an optional callable returning the current time. Used by the verification profiles. Defaults to the system clock.
      def initialize(leeway:, clock: nil)
        @leeway = leeway || 0
        @clock  = clock || -> { Time.now }
      end

      # Verifies the 'nbf' (Not Before) claim in the JWT token.
      #
      # @param context [Object] the context containing the JWT payload.
      # @param _args [Hash] additional arguments (not used).
      # @raise [JWT::ImmatureSignature] if the 'nbf' claim has not been reached.
      # @return [nil]
      def verify!(context:, **_args)
        return unless context.payload.is_a?(Hash)
        return unless context.payload.key?('nbf')

        raise JWT::ImmatureSignature, 'Signature nbf has not been reached' if context.payload['nbf'].to_i > (clock.call.to_i + leeway)
      end

      private

      attr_reader :leeway, :clock
    end
  end
end
