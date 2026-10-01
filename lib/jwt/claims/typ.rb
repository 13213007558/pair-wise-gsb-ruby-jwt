# frozen_string_literal: true

module JWT
  module Claims
    # The Typ class is responsible for validating the 'typ' (type) header of a JWT token.
    #
    # The header type is the natural place to distinguish tokens issued for different
    # purposes (for example an access token vs. a password reset token) when they are
    # signed with the same key. Signature verification alone cannot tell them apart.
    class Typ
      # Initializes a new Typ instance.
      #
      # @param expected_typ [String, Array<String>] the acceptable type(s) for the JWT header.
      def initialize(expected_typ:)
        @expected_typ = Array(expected_typ).map(&:to_s)
      end

      # Verifies the 'typ' header of the JWT token.
      #
      # @param context [Object] the context containing the JWT header.
      # @param _args [Hash] additional arguments (not used).
      # @raise [JWT::InvalidTypError] if the 'typ' header is not one of the expected values.
      # @return [nil]
      def verify!(context:, **_args)
        typ = context.header&.[]('typ')
        return if expected_typ.include?(typ.to_s)

        raise JWT::InvalidTypError, "Invalid typ. Expected #{expected_typ.join(' or ')}, received #{typ || '<none>'}"
      end

      private

      attr_reader :expected_typ
    end
  end
end
