# frozen_string_literal: true

require_relative 'thumbprint'

module JWT
  module JWK
    # JSON Web Key keyfinder
    # To find the key for a given kid
    class KeyFinder
      # Initializes a new KeyFinder instance.
      # @param [Hash] options the options to create a KeyFinder with
      # @option options [Proc, JWT::JWK::Set] :jwks the jwks or a loader proc
      # @option options [Boolean] :allow_nil_kid whether to allow nil kid
      # @option options [Array] :key_fields the fields to use for key matching,
      #                         the order of the fields are used to determine
      #                         the priority of the keys.
      # @option options [Array<String>] :allowed_thumbprints optional whitelist
      #                         of accepted RFC 7638 public key thumbprints.
      #                         An empty whitelist rejects every key.
      def initialize(options)
        @allow_nil_kid = options[:allow_nil_kid]
        jwks_or_loader = options[:jwks]

        @jwks_loader = if jwks_or_loader.respond_to?(:call)
                         jwks_or_loader
                       else
                         ->(_options) { jwks_or_loader }
                       end

        @key_fields = options[:key_fields] || %i[kid]
        @allowed_thumbprints = options[:allowed_thumbprints] || options[:thumbprint_whitelist]
      end

      # Returns the verification key for the given kid
      # @param [String] kid the key id
      # @param [Symbol] key_field the header field the value was read from
      # @param [String] algorithm the algorithm (alg) of the token, used by the
      #   server side selection policy
      def key_for(kid, key_field = :kid, algorithm = nil)
        raise ::JWT::MalformedTokenError, "Invalid type for #{key_field} header parameter" unless kid.nil? || kid.is_a?(String)

        jwk = resolve_key(kid, key_field, algorithm)

        raise ::JWT::SignatureError, 'No keys found in jwks' unless @jwks.any?
        raise ::JWT::SignatureError, "Could not find public key for kid #{kid}" unless jwk

        jwk.verify_key
      end

      # Returns the key for the given token
      # @param [JWT::EncodedToken] token the token
      def call(token)
        key_field, field_value = resolve_key_field(token)
        key_for(field_value, key_field, token.header['alg'])
      end

      private

      def resolve_key_field(token)
        @key_fields.each do |key_field|
          field_value = token.header[key_field.to_s]
          return [key_field, field_value] if field_value
        end

        raise ::JWT::SignatureError, 'No key id (kid) or x5t found from token headers' unless @allow_nil_kid

        [:kid, token.header['kid']]
      end

      def resolve_key(kid, key_field, algorithm)
        policy = SelectionPolicy.new(algorithm: algorithm,
                                     key_field: key_field,
                                     kid: kid,
                                     allow_nil_kid: @allow_nil_kid,
                                     allowed_thumbprints: @allowed_thumbprints)

        # First try without invalidation to facilitate application caching
        @jwks ||= JWT::JWK::Set.new(@jwks_loader.call(key_field => kid))
        jwk = policy.pick(@jwks)

        return jwk if jwk

        # Second try, invalidate for backwards compatibility
        @jwks = JWT::JWK::Set.new(@jwks_loader.call(invalidate: true, kid_not_found: true, key_field => kid))
        policy.pick(@jwks)
      end

      # Server side policy deciding which of the JWKS keys may be used to verify
      # a token. The policy jointly considers the token algorithm together with
      # the JWK +alg+, +kty+, +use+ and +key_ops+ parameters, and an optional
      # public key thumbprint whitelist.
      #
      # Missing metadata is accepted for backwards compatibility. Metadata that
      # is malformed or contradicts itself raises {JWT::JWKError}. Keys that
      # carry metadata but do not fit the token are filtered out. Selection
      # never depends on the order of the keys in the JWKS.
      class SelectionPolicy
        # JWK key types able to run each JWA name prefix.
        KTY_FOR_ALGORITHM_PREFIX = {
          'HS' => 'oct',
          'RS' => 'RSA',
          'PS' => 'RSA',
          'ES' => 'EC'
        }.freeze

        # Key operation values defined by RFC 7517 for signature keys.
        SIGNATURE_KEY_OPERATIONS = %w[sign verify].freeze

        # Initializes a new SelectionPolicy.
        # @param algorithm [String, nil] the +alg+ header of the token
        # @param key_field [Symbol] the header field used for identification
        # @param kid [String, nil] the requested key identifier value
        # @param allow_nil_kid [Boolean] whether keys are accepted without a match
        # @param allowed_thumbprints [Array<String>, nil] optional thumbprint whitelist
        def initialize(algorithm:, key_field:, kid:, allow_nil_kid: false, allowed_thumbprints: nil)
          @algorithm = algorithm
          @key_field = key_field
          @kid = kid
          @allow_nil_kid = allow_nil_kid
          @allowed_thumbprints = allowed_thumbprints.nil? ? nil : Array(allowed_thumbprints).map(&:to_s)
        end

        # Selects the unique acceptable key from the given JWKS.
        #
        # @param jwks [JWT::JWK::Set] the candidate key set
        # @return [JWT::JWK::KeyBase, nil] the unique matching key, or nil when none matches
        # @raise [JWT::AmbiguousKeyError] when more than one distinct key matches
        # @raise [JWT::JWKError] when a matching key carries contradictory metadata
        def pick(jwks)
          candidates = matching_keys(jwks)
          return if candidates.empty?

          unique = collapse_identical_keys(candidates)
          return unique.first if unique.one?

          raise ::JWT::AmbiguousKeyError,
                "Multiple matching keys found in jwks for #{@key_field} #{@kid.inspect}, key selection is ambiguous"
        end

        private

        def matching_keys(jwks)
          jwks.select do |jwk|
            next false unless identifies?(jwk)

            validate_metadata!(jwk)
            acceptable?(jwk)
          end
        end

        def identifies?(jwk)
          (@kid.nil? && @allow_nil_kid) || jwk[@key_field] == @kid
        end

        # Repeated entries of the exact same JWK describe one key, not ambiguity.
        def collapse_identical_keys(jwks)
          jwks.uniq { |jwk| jwk.parameters.hash }
        end

        def acceptable?(jwk)
          algorithm_matches?(jwk) &&
            kty_matches?(jwk) &&
            intended_for_verification?(jwk) &&
            thumbprint_allowed?(jwk)
        end

        # A missing +alg+ is accepted for backwards compatibility. A present
        # +alg+ must be the algorithm of the token.
        def algorithm_matches?(jwk)
          return true if jwk[:alg].nil? || !@algorithm.is_a?(String)

          jwk[:alg].casecmp(@algorithm).zero?
        end

        def kty_matches?(jwk)
          expected_kty.nil? || jwk[:kty] == expected_kty
        end

        # Missing +use+ and +key_ops+ are accepted. A present +use+ must be
        # +sig+ and present +key_ops+ must allow verification.
        def intended_for_verification?(jwk)
          (jwk[:use].nil? || jwk[:use] == 'sig') &&
            (jwk[:key_ops].nil? || jwk[:key_ops].include?('verify'))
        end

        def thumbprint_allowed?(jwk)
          @allowed_thumbprints.nil? ||
            @allowed_thumbprints.include?(::JWT::JWK::Thumbprint.new(jwk).to_s)
        end

        def expected_kty
          return @expected_kty if defined?(@expected_kty)

          @expected_kty = KTY_FOR_ALGORITHM_PREFIX.find do |prefix, _kty|
            @algorithm.is_a?(String) && @algorithm.start_with?(prefix)
          end&.last
        end

        def validate_metadata!(jwk)
          validate_alg!(jwk)
          validate_use!(jwk)
          validate_key_ops!(jwk)
          validate_use_key_ops_consistency!(jwk)
          validate_alg_kty_consistency!(jwk)
        end

        def validate_alg!(jwk)
          return if jwk[:alg].nil? || jwk[:alg].is_a?(String)

          raise ::JWT::JWKError, "Invalid JWK metadata: 'alg' must be a String"
        end

        def validate_use!(jwk)
          return if jwk[:use].nil? || jwk[:use].is_a?(String)

          raise ::JWT::JWKError, "Invalid JWK metadata: 'use' must be a String"
        end

        def validate_key_ops!(jwk)
          key_ops = jwk[:key_ops]
          return if key_ops.nil?
          return if key_ops.is_a?(Array) && key_ops.all? { |op| op.is_a?(String) }

          raise ::JWT::JWKError, "Invalid JWK metadata: 'key_ops' must be an Array of Strings"
        end

        # RFC 7517: when both are present their contents MUST be consistent.
        def validate_use_key_ops_consistency!(jwk)
          return if jwk[:use].nil? || jwk[:key_ops].nil?

          signature_ops = jwk[:key_ops].any? { |op| SIGNATURE_KEY_OPERATIONS.include?(op) }
          inconsistent = (jwk[:use] == 'sig' && !only_signature_operations?(jwk)) ||
                         (jwk[:use] == 'enc' && signature_ops)
          return unless inconsistent

          raise ::JWT::JWKError, "JWK 'use' (#{jwk[:use]}) and 'key_ops' (#{jwk[:key_ops].join(', ')}) are inconsistent"
        end

        def only_signature_operations?(jwk)
          jwk[:key_ops].all? { |op| SIGNATURE_KEY_OPERATIONS.include?(op) }
        end

        # A +alg+ that cannot run on the declared +kty+ is self contradictory.
        def validate_alg_kty_consistency!(jwk)
          return unless jwk[:alg].is_a?(String)

          kty = KTY_FOR_ALGORITHM_PREFIX.find { |prefix, _| jwk[:alg].start_with?(prefix) }&.last
          return if kty.nil? || jwk[:kty] == kty

          raise ::JWT::JWKError, "JWK 'alg' (#{jwk[:alg]}) is incompatible with 'kty' (#{jwk[:kty]})"
        end
      end
    end
  end
end
