# frozen_string_literal: true

require_relative 'validation_profile/rule_violation'

module JWT
  # A reusable, immutable bundle of token validation rules.
  #
  # A profile binds together the type of token accepted ('typ' header), the
  # expected issuer and audience, claims that must be present, claims that must
  # never be present, a maximum token lifetime, the clock and leeway used for
  # time based checks and any number of custom pure validation rules.
  #
  # Profiles are the server's decision, never the token's: the verifier chooses
  # the profile before the token is inspected and a token cannot select, widen
  # or disable any of its rules. Signature verification must happen *before* the
  # profile rules are applied; the profile itself only inspects claims and
  # headers of an already authenticated token.
  #
  # @example Access and password reset tokens sharing one signing key
  #   access_profile = JWT::ValidationProfile.new(
  #     name: 'access',
  #     typ: 'at+JWT',
  #     issuer: 'https://id.example.com',
  #     audience: 'api.example.com',
  #     required_claims: %w[sub iat exp],
  #     forbidden_claims: %w[pwd pwr],
  #     max_lifetime: 900,
  #     leeway: 5
  #   )
  #
  #   reset_profile = JWT::ValidationProfile.new(
  #     name: 'password-reset',
  #     typ: 'reset+JWT',
  #     issuer: 'https://id.example.com',
  #     audience: 'id.example.com',
  #     required_claims: %w[sub iat exp pwr],
  #     forbidden_claims: %w[pwd scope],
  #     max_lifetime: 1800,
  #     leeway: 5
  #   )
  #
  #   # The server picks the profile. A perfectly signed reset token passes its
  #   # own profile but is rejected by the access token profile.
  #   JWT.decode(reset_jwt, shared_key, true, profile: reset_profile)
  #   JWT.decode(reset_jwt, shared_key, true, profile: access_profile)
  #   # => raises JWT::ProfileViolation
  class ValidationProfile
    LIFETIME_CLAIMS = %w[iat exp].freeze

    private_constant(:LIFETIME_CLAIMS)

    # @return [String, Symbol, nil] optional identifier of the profile.
    attr_reader :name

    # @return [Array<String>] the acceptable 'typ' header values.
    attr_reader :typ

    # @return [Array<String>] the acceptable issuer ('iss') claim values.
    attr_reader :issuer

    # @return [Array<String>] the acceptable audience ('aud') claim values.
    attr_reader :audience

    # @return [Array<String>] claims that must be present in the payload.
    attr_reader :required_claims

    # @return [Array<String>] claims that must be absent from the payload.
    attr_reader :forbidden_claims

    # @return [Integer, nil] maximum allowed difference between 'exp' and 'iat' in seconds.
    attr_reader :max_lifetime

    # @return [Integer] clock drift in seconds tolerated by the time based rules.
    attr_reader :leeway

    # @return [#call] callable returning the time used as "now".
    attr_reader :clock

    # Creates a new validation profile. The profile and every rule it contains
    # are frozen and cannot be altered afterwards.
    #
    # @param name [String, Symbol, nil] identifier used in error messages.
    # @param typ [String, Symbol, Array<String, Symbol>, nil] acceptable 'typ'
    #   header value(s). When given, the token header must match exactly.
    # @param issuer [String, Symbol, Array<String, Symbol>, nil] acceptable
    #   'iss' claim value(s). Aliased as +iss+.
    # @param iss [String, Symbol, Array<String, Symbol>, nil] alias of +issuer+.
    # @param audience [String, Symbol, Array<String, Symbol>, nil] acceptable
    #   'aud' claim value(s). Aliased as +aud+.
    # @param aud [String, Symbol, Array<String, Symbol>, nil] alias of +audience+.
    # @param required_claims [Array<String, Symbol>] claims that must be present.
    # @param forbidden_claims [Array<String, Symbol>] claims that must be absent.
    # @param max_lifetime [Integer, nil] maximum number of seconds allowed
    #   between the 'iat' and 'exp' claims. Enforces that both claims exist,
    #   are numeric and that +exp >= iat+.
    # @param leeway [Integer] clock drift in seconds. Leeway only widens the
    #   window of time based checks (exp, nbf, iat, max_lifetime); it never
    #   relaxes structural rules such as required or forbidden claims.
    # @param clock [#call, nil] callable returning the current time. Defaults
    #   to +-> { Time.now }+. Inject a fixed clock for deterministic tests.
    # @param rules [Array<#call>, Hash{#to_sym => #call}] custom pure
    #   validation rules. A plain callable is named +custom+. A hash pairs a
    #   rule name with its callable. Each callable receives +(payload, header)+
    #   and must either return a truthy value, raise JWT::ClaimValidationError
    #   or return +false+/+nil+/a failure message String.
    # @raise [ArgumentError] if an option or a custom rule is invalid.
    def initialize(
      name: nil,
      typ: nil,
      issuer: nil, iss: nil,
      audience: nil, aud: nil,
      required_claims: [],
      forbidden_claims: [],
      max_lifetime: nil,
      leeway: 0,
      clock: nil,
      rules: []
    )
      @name = name

      iss_value = pick_alias(issuer, iss, :issuer, :iss)
      aud_value = pick_alias(audience, aud, :audience, :aud)

      @typ = normalize_strings(typ)
      @issuer = normalize_strings(iss_value)
      @audience = normalize_strings(aud_value)
      @required_claims = normalize_claims(required_claims, :required_claims)
      @forbidden_claims = normalize_claims(forbidden_claims, :forbidden_claims)
      @max_lifetime = validate_non_negative_integer(max_lifetime, :max_lifetime, allow_nil: true)
      @leeway = validate_non_negative_integer(leeway, :leeway)
      @clock = validate_clock(clock)
      @custom_rules = normalize_rules(rules)

      freeze
    end

    # Checks the payload and header against every rule of the profile.
    #
    # All rules are evaluated and every violation is collected, so a single
    # failure report can name every rule the token broke.
    #
    # @overload violations(payload, header = {})
    #   @param payload [Hash] the JWT payload.
    #   @param header [Hash] the JWT header.
    # @overload violations(token)
    #   @param token [#payload, #header] a token like object. An
    #     JWT::EncodedToken is read through +unverified_payload+ when present,
    #     which is only safe after its signature has been verified.
    # @return [Array<RuleViolation>] the violated rules, empty when valid.
    def violations(payload_or_token, header = :none)
      payload, header = coerce_input(payload_or_token, header)
      now = clock.call.to_i

      [].tap do |result|
        collect(result, :typ) { verify_typ(header) }
        collect(result, :iss) { verify_issuer(payload) }
        collect(result, :aud) { verify_audience(payload) }
        collect(result, :required_claims) { verify_required(payload) }
        collect(result, :forbidden_claims) { verify_forbidden(payload) }
        collect(result, :exp) { verify_exp(payload, now) }
        collect(result, :nbf) { verify_nbf(payload, now) }
        collect(result, :iat) { verify_iat(payload, now) }
        collect(result, :max_lifetime) { verify_max_lifetime(payload) }
        @custom_rules.each { |rule_name, callable| collect(result, rule_name) { run_custom(callable, payload, header) } }
      end
    end

    # Returns whether a token satisfies every rule of the profile.
    #
    # @see #violations for the accepted arguments.
    # @return [Boolean] true when no rule is violated.
    def valid?(*args)
      violations(*args).empty?
    end

    # Like {#violations} but raises when any rule is violated.
    #
    # @see #violations for the accepted arguments.
    # @return [nil] when every rule passes.
    # @raise [JWT::ProfileViolation] naming every violated rule.
    def verify!(*args)
      found = violations(*args)
      return nil if found.empty?

      raise JWT::ProfileViolation, failure_message(found)
    end

    private

    def collect(result, rule)
      yield
    rescue JWT::TokenError => e
      result << RuleViolation.new(rule: rule, message: e.message)
    end

    def verify_typ(header)
      return if typ.empty?
      raise JWT::InvalidTokenType, "Invalid typ. Expected one of #{typ.join(', ')}, received #{header['typ'] || '<none>'}" unless header.is_a?(Hash) && typ.include?(header['typ'])
    end

    def verify_issuer(payload)
      return if issuer.empty?

      Claims::Issuer.new(issuers: issuer).verify!(context: context(payload))
    end

    def verify_audience(payload)
      return if audience.empty?

      Claims::Audience.new(expected_audience: audience).verify!(context: context(payload))
    end

    def verify_required(payload)
      Claims::Required.new(required_claims: required_claims).verify!(context: context(payload))
    end

    def verify_forbidden(payload)
      return if forbidden_claims.empty?

      present = forbidden_claims.select { |claim| payload.is_a?(Hash) && payload.key?(claim) }
      raise JWT::InvalidPayload, "Forbidden claim(s) present: #{present.join(', ')}" unless present.empty?
    end

    def verify_exp(payload, now)
      return unless payload.is_a?(Hash) && payload.key?('exp')

      exp = payload['exp']
      raise JWT::InvalidPayload, 'Invalid exp, must be a number' unless exp.is_a?(Numeric)
      raise JWT::ExpiredSignature, 'Signature has expired' if exp.to_i <= (now - leeway)
    end

    def verify_nbf(payload, now)
      return unless payload.is_a?(Hash) && payload.key?('nbf')

      nbf = payload['nbf']
      raise JWT::InvalidPayload, 'Invalid nbf, must be a number' unless nbf.is_a?(Numeric)
      raise JWT::ImmatureSignature, 'Signature nbf has not been reached' if nbf.to_i > (now + leeway)
    end

    def verify_iat(payload, now)
      return unless payload.is_a?(Hash) && payload.key?('iat')

      iat = payload['iat']
      raise JWT::InvalidIatError, 'Invalid iat' if !iat.is_a?(Numeric) || iat.to_i > (now + leeway)
    end

    def verify_max_lifetime(payload)
      return unless max_lifetime

      Claims::Required.new(required_claims: LIFETIME_CLAIMS).verify!(context: context(payload))

      iat = payload['iat']
      exp = payload['exp']
      raise JWT::InvalidPayload, 'Invalid iat and exp for lifetime check, both must be numbers' unless iat.is_a?(Numeric) && exp.is_a?(Numeric)
      raise JWT::InvalidPayload, 'Invalid lifetime, exp must be greater than or equal to iat' if exp < iat

      allowed = iat.to_i + max_lifetime + leeway
      raise JWT::InvalidPayload, "Token lifetime exceeds the maximum of #{max_lifetime} seconds" if exp.to_i > allowed
    end

    def run_custom(callable, payload, header)
      result = callable.call(payload, header)
      # A non empty String is treated as a failure message, false/nil as a
      # nameless failure and everything else truthy as a pass.
      if result.is_a?(String)
        message = result.strip.empty? ? 'Custom validation rule failed' : result
        raise JWT::InvalidPayload, message
      elsif !result
        raise JWT::InvalidPayload, 'Custom validation rule failed'
      end
    end

    def context(payload)
      Claims::VerificationContext.new(payload: payload)
    end

    def coerce_input(payload_or_token, header)
      # A Hash (or nil, which some malformed payloads decode to) is treated as
      # a raw payload. Anything else given on its own must be a token object.
      if header == :none
        if payload_or_token.is_a?(Hash) || payload_or_token.nil?
          [payload_or_token, {}]
        else
          token = payload_or_token
          raise ArgumentError, 'token must respond to #payload' unless token.respond_to?(:payload)

          payload = token.respond_to?(:unverified_payload) ? token.unverified_payload : token.payload
          [payload, token.respond_to?(:header) ? token.header : {}]
        end
      else
        [payload_or_token, header || {}]
      end
    end

    def failure_message(violations)
      prefix = name ? "Validation profile '#{name}' violated: " : 'Validation profile violated: '
      prefix + violations.map(&:to_s).join('; ')
    end

    def pick_alias(primary, aliased, primary_name, alias_name)
      raise ArgumentError, "Provide either :#{primary_name} or :#{alias_name}, not both" unless primary.nil? || aliased.nil?

      primary.nil? ? aliased : primary
    end

    def normalize_strings(value)
      return [] if value.nil?

      Array(value).map do |item|
        item.is_a?(String) ? item : item.to_s
      end.freeze
    end

    def normalize_claims(value, option_name)
      raise ArgumentError, ":#{option_name} must be an Array" unless value.is_a?(Array)

      value.map(&:to_s).freeze
    end

    def validate_non_negative_integer(value, option_name, allow_nil: false)
      return nil if value.nil? && allow_nil
      raise ArgumentError, ":#{option_name} must be an Integer" unless value.is_a?(Integer)
      raise ArgumentError, ":#{option_name} must be greater than or equal to 0" if value.negative?

      value
    end

    def validate_clock(clock)
      clock ||= -> { Time.now }
      raise ArgumentError, ':clock must respond to #call' unless clock.respond_to?(:call)

      clock
    end

    def normalize_rules(rules)
      list =
        case rules
        when Hash
          rules.map { |rule_name, callable| [rule_name.to_sym, callable] }
        when Array
          rules.map { |rule| rule.is_a?(Array) && rule.length == 2 ? [rule[0].to_sym, rule[1]] : [:custom, rule] }
        else
          raise ArgumentError, ':rules must be an Array or a Hash'
        end

      list.each do |rule_name, callable|
        raise ArgumentError, "Rule :#{rule_name} must respond to #call" unless callable.respond_to?(:call)
      end

      list.freeze
    end
  end
end
