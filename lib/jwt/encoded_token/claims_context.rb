# frozen_string_literal: true

require 'forwardable'

module JWT
  # @private
  class EncodedToken
    # Allow access to the unverified payload for claim verification.
    class ClaimsContext
      extend Forwardable

      def_delegators :@token, :header, :unverified_payload, :verified_algorithm

      def initialize(token)
        @token = token
      end

      def payload
        unverified_payload
      end
    end
  end
end
