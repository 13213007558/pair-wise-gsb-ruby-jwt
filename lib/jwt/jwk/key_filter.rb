# frozen_string_literal: true

require_relative 'thumbprint'

module JWT
  module JWK
    # Server side key selection strategy for finding a verification key
    # from a JWKS.
    #
    # The filter jointly checks the JWK metadata against the requirements
    # of signature verification:
    #
    # * +alg+     - when the key carries an +alg+ parameter it must match
    #               the expected algorithm.
    # * +kty+     - the key type must match the key type required by the
    #               expected algorithm (e.g. RS256 requires RSA, HS256
    #               requires oct), unless an explicit +kty+ is configured.
    # * +use+     - when the key carries a +use+ parameter it must match
    #               the expected use ("sig" by default).
    # * +key_ops+ - when the key carries +key_ops+ it must include the
    #               required operation ("verify" by default).
    # * thumbprints - when a whitelist is configured, only keys whose
    #               RFC 7638 public key thumbprint is listed are accepted.
    #
    # Missing metadata is treated as compatible (a key without +use+,
    # +key_ops+ or +alg+ is not restricted by those checks), while
    # metadata contradicting the requirements rejects the key. A key
    # whose own +use+ and +key_ops+ contradict each other is rejected
    # as well.
    class KeyFilter
      # Key operations associated with signature usage
      SIGNATURE_KEY_OPS = %w[sign verify].freeze
      # Key operations associated with encryption usage
      ENCRYPTION_KEY_OPS = %w[encrypt decrypt wrapKey unwrapKey deriveKey deriveBits].freeze

      attr_reader :algorithm, :kty, :use, :key_ops, :thumbprints

      # @param algorithm [String] the expected algorithm. When nil, the
      #        algorithm is taken from the token header.
      # @param kty [String] the expected key type. When nil, the key type
      #        is derived from the expected algorithm.
      # @param use [String, nil] the expected +use+ value ("sig" by default,
      #        nil disables the check).
      # @param key_ops [Array<String>, nil] the required key operations
      #        (["verify"] by default, nil disables the check).
      # @param thumbprints [Array<String>, nil] optional whitelist of
      #        RFC 7638 public key thumbprints.
      def initialize(algorithm: nil, kty: nil, use: 'sig', key_ops: ['verify'], thumbprints: nil)
        @algorithm = algorithm
        @kty = kty
        @use = use
        @key_ops = key_ops && Array(key_ops).map(&:to_s)
        @thumbprints = thumbprints && Array(thumbprints).map(&:to_s)
      end

      # Returns the keys from the given keys that satisfy the filter.
      # @param keys [Array<JWT::JWK::KeyBase>] the keys to filter.
      # @param algorithm [String, nil] the algorithm from the token header.
      # @raise [JWT::IncorrectAlgorithm] if the token algorithm contradicts
      #         the explicitly configured algorithm.
      def select(keys, algorithm: nil)
        expected_algorithm = effective_algorithm(algorithm)
        keys.select { |key| compatible?(key, expected_algorithm) }
      end

      # Returns true if the given key satisfies the filter.
      # @param jwk [JWT::JWK::KeyBase] the key to check.
      # @param algorithm [String, nil] the algorithm from the token header.
      def match?(jwk, algorithm: nil)
        compatible?(jwk, effective_algorithm(algorithm))
      end

      # Maps an algorithm to the key type required by it.
      # Returns nil when the algorithm does not imply a key type.
      def self.kty_for_algorithm(algorithm)
        case algorithm.to_s
        when /\AHS/i        then 'oct'
        when /\A(?:RS|PS)/i then 'RSA'
        when /\AES/i        then 'EC'
        when /\AEdDSA/i     then 'OKP'
        end
      end

      private

      def effective_algorithm(token_algorithm)
        return token_algorithm unless algorithm
        return algorithm unless token_algorithm
        return algorithm if algorithm.to_s.casecmp(token_algorithm.to_s).zero?

        raise ::JWT::IncorrectAlgorithm,
              "Token algorithm #{token_algorithm} does not match the key filter algorithm #{algorithm}"
      end

      def compatible?(jwk, expected_algorithm)
        alg_compatible?(jwk, expected_algorithm) &&
          kty_compatible?(jwk, expected_algorithm) &&
          use_compatible?(jwk) &&
          key_ops_compatible?(jwk) &&
          thumbprint_allowed?(jwk) &&
          !self_contradictory?(jwk)
      end

      def alg_compatible?(jwk, expected_algorithm)
        jwk_alg = jwk[:alg]
        return true unless jwk_alg && expected_algorithm

        jwk_alg.to_s.casecmp(expected_algorithm.to_s).zero?
      end

      def kty_compatible?(jwk, expected_algorithm)
        expected_kty = kty || self.class.kty_for_algorithm(expected_algorithm)
        return true unless expected_kty

        jwk_kty = jwk[:kty]
        return true unless jwk_kty

        jwk_kty.to_s == expected_kty
      end

      def use_compatible?(jwk)
        jwk_use = jwk[:use]
        return true unless jwk_use && use

        jwk_use.to_s == use.to_s
      end

      def key_ops_compatible?(jwk)
        jwk_key_ops = jwk[:key_ops]
        return true unless jwk_key_ops && key_ops

        (key_ops - Array(jwk_key_ops).map(&:to_s)).empty?
      end

      def thumbprint_allowed?(jwk)
        return true unless thumbprints

        thumbprints.include?(::JWT::JWK::Thumbprint.new(jwk).generate)
      end

      def self_contradictory?(jwk)
        jwk_use = jwk[:use]
        jwk_key_ops = jwk[:key_ops]
        return false unless jwk_use && jwk_key_ops

        ops = Array(jwk_key_ops).map(&:to_s)
        case jwk_use.to_s
        when 'sig' then (ops & SIGNATURE_KEY_OPS).empty?
        when 'enc' then (ops & ENCRYPTION_KEY_OPS).empty?
        else false
        end
      end
    end
  end
end
