# frozen_string_literal: true

module JWT
  module JWS
    # Decides whether the set of successfully verified signatures satisfies
    # the caller's acceptance rule.
    #
    # A signer is identified by its key. Signing twice with the same key does
    # therefore never count as two independent signers.
    #
    # @api private
    class Policy
      ALL = :all
      ANY = :any

    # @param policy [Symbol, Integer, Hash] :all, :any, a threshold count or `{ threshold: n }`.
    # @param expected_signers [Integer] number of signers given by the caller.
      def self.from(policy, expected_signers, fixed_keys: false)
        name, threshold = normalize(policy)
        new(name: name,
            threshold: threshold || expected_signers,
            expected_signers: expected_signers,
            fixed_keys: fixed_keys)
      end

      def self.normalize(policy)
        case policy
        when nil, ALL
          [ALL, nil]
        when ANY
          [ANY, 1]
        when ::Integer
          raise ArgumentError, 'The signature threshold must be positive' unless policy.positive?

          [:threshold, policy]
        when ::Hash
          threshold = policy[:threshold] || policy['threshold']
          raise ArgumentError, 'The signature threshold must be an Integer' unless threshold.is_a?(::Integer) && threshold.positive?

          [:threshold, threshold]
        else
          raise ArgumentError, "Unsupported verification policy: #{policy.inspect}"
        end
      end

      def initialize(name:, threshold:, expected_signers:, fixed_keys:)
        @name = name
        @threshold = threshold
        @expected_signers = expected_signers
        @fixed_keys = fixed_keys
      end

      # @param valid_members [Integer] number of signatures that verified successfully.
      # @param invalid_members [Integer] number of signatures present that did not verify.
      # @param distinct_identities [Integer] number of distinct signers that verified.
      # @return [Array(Boolean, String, nil)]
      def satisfied?(valid_members, invalid_members, distinct_identities)
        case @name
        when ALL
          return all_named_signers?(invalid_members, distinct_identities) unless @fixed_keys
          return [true, nil] if invalid_members.zero? && valid_members.positive?

          [false, 'Every signature must verify, but one or more signatures failed']
        else
          if distinct_identities >= @threshold
            [true, nil]
          else
            [false, "At least #{@threshold} independent signer(s) required, got #{distinct_identities}"]
          end
        end
      end

      private

      def all_named_signers?(invalid_members, distinct_identities)
        if invalid_members.zero? && distinct_identities == @expected_signers && @expected_signers.positive?
          [true, nil]
        else
          [false, "Expected all #{@expected_signers} signer(s) to verify, got #{distinct_identities}"]
        end
      end
    end
  end
end
