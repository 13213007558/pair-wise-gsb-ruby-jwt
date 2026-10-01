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

      @segments = jwt.split('.')
      @encoded_header  = @segments[0]
      @encoded_payload = @segments[1] if segment_count >= 2
      @encoded_signature = @segments[2] if segment_count >= 3
      @detached_form = @segments.length >= 2 && @segments[1] == ''
      @external_payload_provided = false
    end

    # Tells whether the token is a detached payload JWS (RFC 7515 appendix F),
    # i.e. the compact serialization has an empty payload segment.
    #
    # The result reflects the original token form and does not change when the
    # external payload is supplied through {#encoded_payload=}.
    #
    # @return [Boolean] true when the token has the detached payload form.
    def detached?
      @detached_form
    end

    # Tells whether the payload is transported unencoded as described in RFC 7797.
    #
    # @return [Boolean] true when the 'b64' header is explicitly false.
    def unencoded?
      header['b64'] == false
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

    # Sets the external payload carried separately from a detached payload JWS.
    #
    # The value is used verbatim as the signing input payload. For an RFC 7797
    # unencoded token ('b64' header false) the value is the raw payload bytes,
    # otherwise it is the base64url encoded payload of a regular JWT.
    #
    # Providing an empty String is a valid, distinct payload and must not be
    # confused with not providing the external payload at all.
    #
    # Resets the verification state, requiring the token to be verified again.
    #
    # @param encoded_payload [String] the external payload bytes.
    # @raise [JWT::MalformedTokenError] if the value is not a String or contains
    #   a '.' character while the token carries an unencoded payload.
    def encoded_payload=(encoded_payload)
      unless encoded_payload.is_a?(String)
        raise JWT::MalformedTokenError, 'The payload must be a String containing the original bytes'
      end
      if inline_unencoded_payload?(encoded_payload)
        raise JWT::MalformedTokenError, "Invalid unencoded payload, '.' character is not allowed in the payload"
      end

      @encoded_payload = encoded_payload
      @external_payload_provided = true
      @decoded_payload = nil
      @signature_verified = @claims_verified = false
    end

    # Returns the signing input of the JWT token.
    #
    # For an RFC 7797 unencoded payload the raw payload bytes are used instead
    # of the base64url encoded representation.
    #
    # @return [String] the signing input.
    # @raise [JWT::MalformedTokenError] if the token is structurally invalid or
    #   a detached payload is expected but has not been provided.
    def signing_input
      validate_structure!
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
    # @return [nil]
    # @raise [JWT::Error] if the signature or claim verification fails.
    def verify!(signature:, claims: nil)
      verify_signature!(**signature)
      claims.is_a?(Array) ? verify_claims!(*claims) : verify_claims!(claims)
      nil
    end

    # Verifies the token signature and claims.
    # By default it verifies the 'exp' claim.

    # @param signature [Hash] the parameters for signature verification (see {#verify_signature!}).
    # @param claims [Array<Symbol>, Hash] the claims to verify (see {#verify_claims!}).
    # @return [Boolean] true if the signature and claims are valid, false otherwise.
    def valid?(signature:, claims: nil)
      valid_signature?(**signature) &&
        (claims.is_a?(Array) ? valid_claims?(*claims) : valid_claims?(claims))
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

      validate_structure!

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

    alias to_s jwt

    private

    def claims_options(options)
      return DEFAULT_CLAIMS if options.first.nil?

      options
    end

    def decode_payload
      validate_structure!

      if unencoded?
        # RFC 7797: the payload is not base64url decoded and may be arbitrary
        # bytes, not even JSON. The original bytes supplied by the caller are
        # returned verbatim.
        raise JWT::MalformedTokenError, 'The payload is detached and must be provided separately' if detached_payload_missing?

        return encoded_payload
      end

      raise JWT::MalformedTokenError, 'Encoded payload is empty' if encoded_payload.nil? || encoded_payload == ''

      parse_and_decode(encoded_payload)
    end

    # Validates the compact serialization and the JWS headers relevant for
    # RFC 7797. The header is not authenticated until the signature is verified,
    # so a malformed structure must never reach the signature computation.
    def validate_structure!
      unless (2..3).cover?(segment_count)
        raise JWT::MalformedTokenError, 'Not enough or too many segments'
      end

      validate_b64_header!
    end

    def validate_b64_header!
      return unless header.is_a?(Hash)

      b64 = header['b64']

      return if b64.nil? || b64 == true
      unless b64 == false
        raise JWT::MalformedTokenError, "The 'b64' header must be a boolean value"
      end

      unless header['crit'].is_a?(Array) && header['crit'].include?('b64')
        raise JWT::MalformedTokenError, "The 'b64' critical header must be declared in the crit header"
      end

      # RFC 7797 section 3: '.' is not allowed in an unencoded compact payload.
      raise JWT::MalformedTokenError, "Invalid unencoded payload, '.' character is not allowed in the payload" if segment_count == 3 && inline_unencoded_payload?(encoded_payload)
      raise JWT::MalformedTokenError, 'The payload is detached and must be provided separately' if detached_payload_missing?
    end

    def detached_payload_missing?
      detached? && !@external_payload_provided
    end

    # The compact serialization cannot carry an unencoded payload with '.' in
    # it. A payload containing '.' is only acceptable when carried detached.
    def inline_unencoded_payload?(payload)
      unencoded? && !detached? && payload.include?('.')
    end

    def segment_count
      @segments.length
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
