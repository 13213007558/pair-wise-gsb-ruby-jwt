# frozen_string_literal: true

module JWT
  module Claims
    # The Expiration class is responsible for validating the expiration claim ('exp') in a JWT token.
    class Expiration
      # Initializes a new Expiration instance.
      #
      # @param leeway [Integer] the amount of leeway (in seconds) to allow when validating the expiration time. Default: 0.
      # @param clock [#call] an optional callable returning the current time. Used by the verification profiles. Defaults to the system clock.
      def initialize(leeway:, clock: nil)
        @leeway = leeway || 0
        @clock  = clock || -> { Time.now }
      end

      # Verifies the expiration claim ('exp') in the JWT token.
      #
      # @param context [Object] the context containing the JWT payload.
      # @param _args [Hash] additional arguments (not used).
      # @raise [JWT::ExpiredSignature] if the token has expired.
      # @return [nil]
      def verify!(context:, **_args)
        return unless context.payload.is_a?(Hash)
        return unless context.payload.key?('exp')

        raise JWT::ExpiredSignature, 'Signature has expired' if context.payload['exp'].to_i <= (clock.call.to_i - leeway)
      end

      private

      attr_reader :leeway, :clock
    end
  end
end
