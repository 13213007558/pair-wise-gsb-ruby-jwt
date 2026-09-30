# frozen_string_literal: true

module JWT
  module SDJwt
    # Marks a claim or array element as selectively disclosable.
    class Disclosable
      attr_reader :value, :salt

      def initialize(value, salt: nil)
        @value = value
        @salt = salt
      end
    end
  end
end
