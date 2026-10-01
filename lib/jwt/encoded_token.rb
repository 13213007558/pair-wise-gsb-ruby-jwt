# frozen_string_literal: true

require_relative 'encoded_token/claims_context'

module JWT
  # Represents an encoded JWT token
  #
  # Processing an encoded and signed token:
  #
  #   token = JWT::Token.new(payload: {pay: 'load'})
  #   token.sign!(algorithm: 'HS256', key: 'secret')
  #
  #   encoded_token = JWT::EncodedToken.new(token.jwt)
  #   encoded_token.verify_signature!(algorithm: 'HS256', key: 'secret')
  #   encoded_token.payload # => {'pay' => 'load'}
  class EncodedToken
    DEFAULT_CLAIMS = [:exp].freeze

    private_constant(:DEFAULT_CLAIMS)

    # Returns the original token provided to the class.
    # @return [String] The JWT token.
    attr_reader :jwt

    # Initializes a new EncodedToken instance.
    #
    # @param jwt [String] the encoded JWT token.
    # @raise [ArgumentError] if the provided JWT is not a String.
    def initialize(jwt)
      raise ArgumentError, 'Provided JWT must be a String' unless jwt.is_a?(String)

      @jwt = jwt
      @signature_verified = false
      @claims_verified    = false

      @encoded_header, @encoded_payload, @encoded_signature = jwt.split('.')
    end

    # Returns the decoded signature of the JWT token.
    #
    # @return [String] the decoded signature.
    def signature
      @signature ||= ::JWT::Base64.url_decode(encoded_signature || '')
    end

    # Returns the encoded signature of the JWT token.
    #
    # @return [String] the encoded signature.
    attr_reader :encoded_signature

    # Returns the decoded header of the JWT token.
    #
    # @return [Hash] the header.
    def header
      @header ||= parse_and_decode(@encoded_header)
    end

    # Returns the encoded header of the JWT token.
    #
    # @return [String] the encoded header.
    attr_reader :encoded_header

    # Returns the payload of the JWT token. Access requires the signature and claims to have been verified.
    #
    # @return [Hash] the payload.
    # @raise [JWT::TokenError] if the signature has not been verified.
    def payload
      raise JWT::TokenError, 'Verify the token signature before accessing the payload' unless @signature_verified
      raise JWT::TokenError, 'Verify the token claims before accessing the payload' unless @claims_verified

      decoded_payload
    end

    # Returns the payload of the JWT token without requiring the signature to have been verified.
    # @return [Hash] the payload.
    def unverified_payload
      decoded_payload
    end

    # Returns the encoded payload of the JWT token.
    #
    # @return [String] the encoded payload.
    attr_reader :encoded_payload

    # Sets the encoded payload of the JWT token.
    #
    # Resets the verification state, requiring the token to be verified again.
    #
    # @param encoded_payload [String] the encoded payload.
    def encoded_payload=(encoded_payload)
      @encoded_payload = encoded_payload
      @decoded_payload = nil
      @signature_verified = @claims_verified = false
    end

    # Returns the signing input of the JWT token.
    #
    # @return [String] the signing input.
    def signing_input
      [encoded_header, encoded_payload].join('.')
    end

    # Verifies the token signature and claims.
    # By default it verifies the 'exp' claim.
    #
    # @example
    #  encoded_token.verify!(signature: { algorithm: 'HS256', key: 'secret' }, claims: [:exp])
    #
    # @param signature [Hash] the parameters for signature verification (see {#verify_signature!}).
    # @param claims [Array<Symbol>, Hash] the claims to verify (see {#verify_claims!}).
    # @param profile [JWT::ValidationProfile, #verify!] an optional server selected
    #   validation profile. When given it fully replaces the +claims+ rules and is
    #   applied only after the signature is verified.
    # @return [nil]
    # @raise [JWT::Error] if the signature or claim verification fails.
    def verify!(signature:, claims: nil, profile: nil)
      verify_signature!(**signature)
      profile ? verify_profile!(profile) : (claims.is_a?(Array) ? verify_claims!(*claims) : verify_claims!(claims))
      nil
    end

    # Verifies the token signature and claims.
    # By default it verifies the 'exp' claim.

    # @param signature [Hash] the parameters for signature verification (see {#verify_signature!}).
    # @param claims [Array<Symbol>, Hash] the claims to verify (see {#verify_claims!}).
    # @param profile [JWT::ValidationProfile, #verify!] an optional server selected
    #   validation profile (see {#verify!}).
    # @return [Boolean] true if the signature and claim rules are valid, false otherwise.
    def valid?(signature:, claims: nil, profile: nil)
      valid_signature?(**signature) &&
        if profile
          valid_profile?(profile)
        else
          claims.is_a?(Array) ? valid_claims?(*claims) : valid_claims?(claims)
        end
    end

    # Verifies the signature of the JWT token.
    #
    # @param algorithm [String, Array<String>, Object, Array<Object>] the algorithm(s) to use for verification.
    # @param key [String, Array<String>] the key(s) to use for verification.
    # @param key_finder [#call] an object responding to `call` to find the key for verification.
    # @return [nil]
    # @raise [JWT::VerificationError] if the signature verification fails.
    # @raise [ArgumentError] if neither key nor key_finder is provided, or if both are provided.
    def verify_signature!(algorithm:, key: nil, key_finder: nil)
      return if valid_signature?(algorithm: algorithm, key: key, key_finder: key_finder)

      raise JWT::VerificationError, 'Signature verification failed'
    end

    # Checks if the signature of the JWT token is valid.
    #
    # @param algorithm [String, Array<String>, Object, Array<Object>] the algorithm(s) to use for verification.
    # @param key [String, Array<String>, JWT::JWK::KeyBase, Array<JWT::JWK::KeyBase>] the key(s) to use for verification.
    # @param key_finder [#call] an object responding to `call` to find the key for verification.
    # @return [Boolean] true if the signature is valid, false otherwise.
    def valid_signature?(algorithm: nil, key: nil, key_finder: nil)
      raise ArgumentError, 'Provide either key or key_finder, not both or neither' if key.nil? == key_finder.nil?

      keys      = Array(key || key_finder.call(self))
      verifiers = JWA.create_verifiers(algorithms: algorithm, keys: keys, preferred_algorithm: header['alg'])

      raise JWT::VerificationError, 'No algorithm provided' if verifiers.empty?

      valid = verifiers.any? do |jwa|
        jwa.verify(data: signing_input, signature: signature)
      end
      valid.tap { |verified| @signature_verified = verified }
    end

    # Verifies the claims of the token.
    # @param options [Array<Symbol>, Hash] the claims to verify. By default, it checks the 'exp' claim.
    # @raise [JWT::ClaimValidationError] if the claims are invalid.
    # @raise [JWT::MalformedTokenError] if the payload cannot be decoded, which happens before any claim is validated.
    def verify_claims!(*options)
      Claims::Verifier.verify!(ClaimsContext.new(self), *claims_options(options)).tap do
        @claims_verified = true
      end
    rescue StandardError
      @claims_verified = false
      raise
    end

    # Returns the errors of the claims of the token.
    # @param options [Array<Symbol>, Hash] the claims to verify. By default, it checks the 'exp' claim.
    # @return [Array<Symbol>] the errors of the claims.
    def claim_errors(*options)
      Claims::Verifier.errors(ClaimsContext.new(self), *claims_options(options))
    end

    # Returns whether the claims of the token are valid.
    # @param options [Array<Symbol>, Hash] the claims to verify. By default, it checks the 'exp' claim.
    # @return [Boolean] whether the claims are valid.
    def valid_claims?(*options)
      claim_errors(*claims_options(options)).empty?.tap { |verified| @claims_verified = verified }
    end

    # Verifies the token against a server selected validation profile.
    # The signature must have been verified first (see {#verify_signature!}).
    #
    # @param profile [JWT::ValidationProfile, #verify!] the profile to apply.
    # @return [nil]
    # @raise [JWT::ProfileViolation] if the token violates the profile.
    # @raise [ArgumentError] if the profile does not respond to +#verify!+.
    def verify_profile!(profile)
      raise ArgumentError, 'profile must respond to #verify!' unless profile.respond_to?(:verify!)

      profile.verify!(ClaimsContext.new(self)).tap { @claims_verified = true }
    rescue StandardError
      @claims_verified = false
      raise
    end

    # Checks the token against a server selected validation profile.
    #
    # @param profile [JWT::ValidationProfile, #verify!] the profile to apply.
    # @return [Boolean] whether the token satisfies every profile rule.
    def valid_profile?(profile)
      verify_profile!(profile)
      true
    rescue JWT::ClaimValidationError
      false
    end

    alias to_s jwt

    private

    def claims_options(options)
      return DEFAULT_CLAIMS if options.first.nil?

      options
    end

    def decode_payload
      raise JWT::MalformedTokenError, 'Encoded payload is empty' if encoded_payload == ''

      if unencoded_payload?
        verify_claims!(crit: ['b64'])
        return parse(encoded_payload)
      end

      parse_and_decode(encoded_payload)
    end

    def unencoded_payload?
      header['b64'] == false
    end

    def parse_and_decode(segment)
      parse(::JWT::Base64.url_decode(segment || ''))
    end

    def parse(segment)
      JWT::JSON.parse(segment)
    rescue ::JSON::ParserError
      raise JWT::MalformedTokenError, 'Invalid segment encoding'
    end

    def decoded_payload
      @decoded_payload ||= decode_payload
    end
  end
end
