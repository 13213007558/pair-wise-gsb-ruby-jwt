# frozen_string_literal: true

module JWT
  module JWS
    # Decides when a JWS carrying several signatures can be considered verified.
    #
    # Two kinds of policies are supported:
    #
    # [+:all+] every signature must be valid and the valid signatures must come
    #          from distinct keys. A valid signature can therefore never mask an
    #          invalid sibling.
    # [Integer] at least the given number of distinct keys must have produced a
    #           valid signature.
    module Policy
      # Builds a policy from the caller provided value.
      #
      # @param policy [Symbol, Integer, Hash, nil] the requested policy.
      # @return [#satisfied?] the policy implementation.
      def self.build(policy)
        case policy
        when nil, :all, :all_signatures
          AllSignatures.new
        when ::Integer
          Threshold.new(policy)
        when ::Hash
          threshold = policy[:minimum] || policy[:threshold]
          raise ::ArgumentError, 'Threshold policy requires a :minimum number of signers' unless threshold.is_a?(::Integer)

          Threshold.new(threshold)
        else
          raise ::ArgumentError, "Unknown JWS verification policy: #{policy.inspect}"
        end
      end

      # Every signature has to be valid and backed by a distinct key.
      class AllSignatures
        # @param results [Array<JWT::JWS::SignatureResult>] per-signature results.
        # @return [Boolean]
        def satisfied?(results)
          return false if results.empty?
          return false unless results.all?(&:valid?)

          valid_identities(results).size == results.size
        end

        # @param results [Array<JWT::JWS::SignatureResult>] per-signature results.
        # @return [String] human readable state of the policy.
        def description(results)
          identities = valid_identities(results)
          "expected all #{results.size} signature(s) from distinct keys, got #{identities.size} distinct valid signer(s)"
        end

        private

        def valid_identities(results)
          results.select(&:valid?).map(&:key_identity).compact.uniq
        end
      end

      # At least a number of distinct keys must have produced valid signatures.
      class Threshold
        # @return [Integer] the required number of distinct valid signers.
        attr_reader :minimum

        def initialize(minimum)
          raise ::ArgumentError, 'Threshold must be a positive integer' unless minimum.positive?

          @minimum = minimum
        end

        # @param results [Array<JWT::JWS::SignatureResult>] per-signature results.
        # @return [Boolean]
        def satisfied?(results)
          valid_identities(results).size >= minimum
        end

        # @param results [Array<JWT::JWS::SignatureResult>] per-signature results.
        # @return [String] human readable state of the policy.
        def description(results)
          "expected #{minimum} distinct valid signer(s), got #{valid_identities(results).size}"
        end

        private

        def valid_identities(results)
          results.select(&:valid?).map(&:key_identity).compact.uniq
        end
      end
    end
  end
end
