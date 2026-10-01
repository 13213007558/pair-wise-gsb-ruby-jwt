# frozen_string_literal: true

module JWT
  module Claims
    # The MaxLifetime class enforces a cross-claim constraint: the span between the
    # issued at ('iat') and expiration ('exp') claims must not exceed the configured
    # maximum lifetime. Both claims must be present and numeric.
    #
    # Because this is a difference between two timestamps in the same token, neither
    # the verifier clock nor leeway play a role here: the lifetime is independent of
    # the current time.
    class MaxLifetime
      # Initializes a new MaxLifetime instance.
      #
      # @param max_lifetime [Numeric] the maximum allowed lifetime, in seconds.
      def initialize(max_lifetime:)
        raise ArgumentError, 'max_lifetime must be a Numeric number of seconds' unless max_lifetime.is_a?(::Numeric)
        raise ArgumentError, 'max_lifetime must be greater than zero' unless max_lifetime.positive?

        @max_lifetime = max_lifetime
      end

      # Verifies the token lifetime against the configured maximum.
      #
      # @param context [Object] the context containing the JWT payload.
      # @param _args [Hash] additional arguments (not used).
      # @raise [JWT::MissingRequiredClaim] if 'iat' or 'exp' is missing.
      # @raise [JWT::InvalidPayload] if 'iat' or 'exp' is not numeric, or exp precedes iat.
      # @raise [JWT::MaxLifetimeExceeded] if the lifetime exceeds the maximum.
      # @return [nil]
      def verify!(context:, **_args)
        payload = context.payload
        return unless payload.is_a?(Hash)

        iat = numeric_claim(payload, 'iat')
        exp = numeric_claim(payload, 'exp')

        lifetime = exp - iat
        raise JWT::InvalidPayload, 'The exp claim must not precede the iat claim' if lifetime.negative?
        return if lifetime <= max_lifetime

        raise JWT::MaxLifetimeExceeded,
              "Token lifetime of #{lifetime} seconds exceeds the maximum allowed lifetime of #{max_lifetime} seconds"
      end

      private

      attr_reader :max_lifetime

      def numeric_claim(payload, claim)
        unless payload.key?(claim)
          raise JWT::MissingRequiredClaim, "Missing required claim #{claim}"
        end
        value = payload[claim]
        return value if value.is_a?(::Numeric)

        raise JWT::InvalidPayload, "#{claim} claim must be a Numeric value but it is a #{value.class}"
      end
    end
  end
end
