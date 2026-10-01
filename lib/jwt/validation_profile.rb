# frozen_string_literal: true

module JWT
  # A reusable, immutable bundle of token verification rules.
  #
  # Signature verification proves who issued a token, but tokens minted for
  # different purposes (for example an access token and a password reset token)
  # may be signed with the exact same key. Signature verification on its own
  # cannot tell them apart, so a perfectly valid reset token would also be
  # accepted as an access token.
  #
  # A ValidationProfile binds the expected type, issuer and audience together
  # with required and forbidden claims, a maximum lifetime, temporal checks and
  # arbitrary custom rules into one frozen configuration. The server chooses
  # which profile applies to an endpoint; the token can never select looser
  # rules for itself.
  #
  # Claim rules are only evaluated *after* the signature has been verified.
  # Verification collects every violated rule and raises a single
  # {JWT::ProfileViolation} that names the broken rules. Signature keys and key
  # material are never included in the result.
  #
  # @example Access and password reset profiles sharing one signing key
  #   access_profile = JWT::ValidationProfile.new(
  #     name: :access,
  #     typ: 'access',
  #     issuer: 'https://id.example.com',
  #     audience: 'api.example.com',
  #     required_claims: %w[sub iat exp],
  #     forbidden_claims: %w[reset_purpose],
  #     max_lifetime: 15 * 60
  #   )
  #
  #   reset_profile = JWT::ValidationProfile.new(
  #     name: :password_reset,
  #     typ: 'password_reset',
  #     issuer: 'https://id.example.com',
  #     audience: 'id.example.com',
  #     required_claims: %w[sub iat exp reset_purpose],
  #     forbidden_claims: %w[scope],
  #     max_lifetime: 5 * 60
  #   )
  #
  #   # After signature verification, chosen server-side at each endpoint:
  #   access_profile.verify!(encoded_token)
  class ValidationProfile
    # A single rule violation found while evaluating a profile.
    Violation = Struct.new(:rule, :message, keyword_init: true)

    # Adapts a custom, pure verification rule. A rule is either an object
    # responding to <tt>verify!(context:)</tt> (like the built-in claim
    # verifiers) or any callable that receives the context and returns a
    # result. A rule signals a violation by raising a
    # {JWT::ClaimValidationError}; return values are ignored.
    #
    # @api private
    class CustomRule
      def initialize(name, rule)
        @name = name
        @rule = rule
      end

      attr_reader :name

      def verify!(context:)
        if @rule.respond_to?(:verify!)
          @rule.verify!(context: context)
        else
          @rule.call(context)
        end
      end
    end

    # @!attribute [r] name
    #   @return [Symbol, String, nil] optional label included in error messages.
    # @!attribute [r] expected_typ
    #   @return [Array<String>] the accepted 'typ' header values.
    # @!attribute [r] issuers
    #   @return [Array<String>] the accepted 'iss' claim values.
    # @!attribute [r] expected_audience
    #   @return [Array<String>] the accepted 'aud' claim values.
    # @!attribute [r] required_claims
    #   @return [Array<String>] claims that must be present in the payload.
    # @!attribute [r] forbidden_claims
    #   @return [Array<String>] claims that must not be present in the payload.
    # @!attribute [r] leeway
    #   @return [Numeric] clock skew tolerance in seconds for exp, nbf and iat.
    # @!attribute [r] max_lifetime
    #   @return [Numeric, nil] maximum allowed exp - iat span in seconds.
    attr_reader :name,
                :expected_typ,
                :issuers,
                :expected_audience,
                :required_claims,
                :forbidden_claims,
                :leeway,
                :max_lifetime

    # rubocop:disable Metrics/ParameterLists, Metrics/AbcSize, Metrics/MethodLength

    # Initializes a new immutable validation profile.
    #
    # @param name [String, Symbol, nil] optional label used in error messages.
    # @param typ [String, Array<String>, nil] accepted 'typ' header value(s).
    # @param issuer [String, Array<String>, nil] accepted 'iss' claim value(s).
    # @param audience [String, Array<String>, nil] accepted 'aud' claim value(s).
    # @param required_claims [Array<String>] claims that must be present.
    # @param forbidden_claims [Array<String>] claims that must not be present.
    # @param max_lifetime [Numeric, nil] maximum allowed exp - iat span in seconds.
    # @param leeway [Numeric] clock skew tolerance in seconds for exp, nbf and iat.
    # @param clock [#call, nil] callable returning the current time, defaults to the system clock.
    # @param verify_expiration [Boolean] whether to validate the 'exp' claim.
    # @param verify_not_before [Boolean] whether to validate the 'nbf' claim.
    # @param verify_issued_at [Boolean] whether to validate the 'iat' claim.
    # @param verify_numeric [Boolean] whether to validate numeric claims.
    # @param rules [Array<#verify!>, Hash] custom verification rules. Objects are named after
    #   their class; a Hash maps explicit rule names to objects or callables. See {CustomRule}.
    def initialize(
      name: nil,
      typ: nil,
      issuer: nil,
      audience: nil,
      required_claims: [],
      forbidden_claims: [],
      max_lifetime: nil,
      leeway: 0,
      clock: nil,
      verify_expiration: true,
      verify_not_before: true,
      verify_issued_at: true,
      verify_numeric: true,
      rules: []
    )
      validate_time_options!(max_lifetime, leeway)

      @name              = name
      @expected_typ      = Array(typ).map(&:to_s).freeze
      @issuers           = Array(issuer).map(&:to_s).freeze
      @expected_audience = Array(audience).map(&:to_s).freeze
      @required_claims   = Array(required_claims).map(&:to_s).freeze
      @forbidden_claims  = Array(forbidden_claims).map(&:to_s).freeze
      @max_lifetime      = max_lifetime
      @leeway            = leeway
      @clock             = (clock || -> { Time.now }).freeze

      @rules = build_rules(
        verify_expiration: verify_expiration,
        verify_not_before: verify_not_before,
        verify_issued_at: verify_issued_at,
        verify_numeric: verify_numeric,
        custom_rules: rules
      ).freeze

      freeze
    end
    # rubocop:enable Metrics/ParameterLists, Metrics/AbcSize, Metrics/MethodLength

    # Evaluates all profile rules against a signature-verified token.
    #
    # @param target [JWT::EncodedToken, JWT::Token, #payload, #header, Hash]
    #   the token or raw payload hash to validate. When verifying live traffic
    #   pass the {JWT::EncodedToken} only after its signature has been checked.
    # @return [Array<Violation>] every violated rule, empty when the token is valid.
    def violations(target)
      context = build_context(target)
      rules.each_with_object([]) do |(rule_name, verifier), result|
        verifier.verify!(context: context)
      rescue JWT::ClaimValidationError, JWT::MalformedTokenError => e
        result << Violation.new(rule: rule_name, message: e.message)
      end
    end

    # @param target [JWT::EncodedToken, JWT::Token, #payload, #header, Hash] the token or payload to validate.
    # @return [Boolean] true when no profile rule is violated.
    def valid?(target)
      violations(target).empty?
    end

    # @param target [JWT::EncodedToken, JWT::Token, #payload, #header, Hash] the token or payload to validate.
    # @return [nil]
    # @raise [JWT::ProfileViolation] naming every rule the token violated.
    def verify!(target)
      found = violations(target)
      raise JWT::ProfileViolation.new(name, found) unless found.empty?

      nil
    end

    private

    attr_reader :clock, :rules

    def validate_time_options!(max_lifetime, leeway)
      if max_lifetime && (!max_lifetime.is_a?(::Numeric) || !max_lifetime.positive?)
        raise ArgumentError, 'max_lifetime must be a positive Numeric number of seconds'
      end
      return if leeway.is_a?(::Numeric) && !leeway.negative?

      raise ArgumentError, 'leeway must be a non-negative Numeric number of seconds'
    end

    # rubocop:disable Metrics/ParameterLists, Metrics/AbcSize, Metrics/MethodLength
    def build_rules(verify_expiration:, verify_not_before:, verify_issued_at:, verify_numeric:, custom_rules:)
      built = []

      built << [:typ, Claims::Typ.new(expected_typ: expected_typ)] unless expected_typ.empty?
      built << [:iss, Claims::Issuer.new(issuers: issuers)] unless issuers.empty?
      built << [:aud, Claims::Audience.new(expected_audience: expected_audience)] unless expected_audience.empty?
      built << [:required, Claims::Required.new(required_claims: required_claims)] unless required_claims.empty?
      built << [:forbidden, Claims::Forbidden.new(forbidden_claims: forbidden_claims)] unless forbidden_claims.empty?
      built << [:numeric, Claims::Numeric.new] if verify_numeric
      built << [:exp, Claims::Expiration.new(leeway: leeway, clock: clock)] if verify_expiration
      built << [:nbf, Claims::NotBefore.new(leeway: leeway, clock: clock)] if verify_not_before
      built << [:iat, Claims::IssuedAt.new(leeway: leeway, clock: clock)] if verify_issued_at
      built << [:max_lifetime, Claims::MaxLifetime.new(max_lifetime: max_lifetime)] if max_lifetime

      built.concat(normalize_custom_rules(custom_rules))
      built
    end
    # rubocop:enable Metrics/ParameterLists, Metrics/AbcSize, Metrics/MethodLength

    def normalize_custom_rules(rules)
      pairs = rules.is_a?(Hash) ? rules.to_a : Array(rules).map { |rule| [default_rule_name(rule), rule] }
      pairs.map do |rule_name, rule|
        unless rule.respond_to?(:verify!) || rule.respond_to?(:call)
          raise ArgumentError, "Custom rule #{rule_name} must respond to verify!(context:) or call(context)"
        end

        [rule_name.to_sym, CustomRule.new(rule_name.to_sym, rule)]
      end
    end

    def default_rule_name(rule)
      rule.class.name ? rule.class.name.split('::').last.downcase.to_sym : :custom_rule
    end

    def build_context(target)
      case target
      when Hash
        Claims::VerificationContext.new(payload: target)
      else
        raise ArgumentError, 'Validation target must be a token or a payload Hash' unless target.respond_to?(:payload)

        # EncodedToken exposes unverified_payload because its guarded #payload
        # accessor also expects claim verification; the profile itself provides
        # that step. Signature verification remains the caller's responsibility
        # and always happens first in the JWT.decode flow.
        payload = if target.respond_to?(:unverified_payload)
                    target.unverified_payload
                  else
                    target.payload
                  end
        Claims::VerificationContext.new(
          payload: payload,
          header: target.respond_to?(:header) ? target.header : nil
        )
      end
    end
  end
end
