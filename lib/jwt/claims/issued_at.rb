# frozen_string_literal: true

module JWT
  module Claims
    # The IssuedAt class is responsible for validating the issued at claim ('iat') in a JWT token.
    class IssuedAt
      # Initializes a new IssuedAt instance.
      #
      # @param leeway [Integer] the drift (in seconds) to allow between the clock of the issuer and the clock of the verifier. Default: 0.
      # @param clock [#call] an optional callable returning the current time. Used by the verification profiles. Defaults to the system clock.
      def initialize(leeway: 0, clock: nil)
        @leeway = leeway || 0
        @clock  = clock || -> { Time.now }
      end

      # Verifies the issued at claim ('iat') in the JWT token.
      #
      # @param context [Object] the context containing the JWT payload.
      # @param _args [Hash] additional arguments (not used).
      # @raise [JWT::InvalidIatError] if the issued at claim is invalid.
      # @return [nil]
      def verify!(context:, **_args)
        return unless context.payload.is_a?(Hash)
        return unless context.payload.key?('iat')

        iat = context.payload['iat']
        raise(JWT::InvalidIatError, 'Invalid iat') if !iat.is_a?(::Numeric) || iat.to_f > (clock.call.to_f + leeway)
      end

      private

      attr_reader :leeway, :clock
    end
  end
end
