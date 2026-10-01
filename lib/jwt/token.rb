# frozen_string_literal: true

module JWT
  # Represents a JWT token
  #
  # Basic token signed using the HS256 algorithm:
  #
  #   token = JWT::Token.new(payload: {pay: 'load'})
  #   token.sign!(algorithm: 'HS256', key: 'secret')
  #   token.jwt # => eyJhb....
  #
  # Custom headers will be combined with generated headers:
  #   token = JWT::Token.new(payload: {pay: 'load'}, header: {custom: "value"})
  #   token.sign!(algorithm: 'HS256', key: 'secret')
  #   token.header # => {"custom"=>"value", "alg"=>"HS256"}
  #
  class Token
    # Initializes a new Token instance.
    #
    # @param header [Hash] the header of the JWT token.
    # @param payload [Hash] the payload of the JWT token.
    def initialize(payload:, header: {})
      @header  = header&.transform_keys(&:to_s)
      @payload = payload
    end

    # Builds a Token from already encoded JWS segments.
    #
    # @param encoded_header [String] the Base64url encoded header.
    # @param encoded_payload [String] the Base64url encoded payload.
    # @param signature [String] the raw signature bytes.
    # @return [Token]
    # @api private
    def self.from_encoded_segments(encoded_header:, encoded_payload:, signature:)
      allocate.tap do |token|
        token.instance_variable_set(:@encoded_header, encoded_header)
        token.instance_variable_set(:@encoded_payload, encoded_payload)
        token.instance_variable_set(:@signature, signature)
      end
    end

    # Returns the decoded signature of the JWT token.
    #
    # @return [String] the decoded signature of the JWT token.
    def signature
      @signature ||= ::JWT::Base64.url_decode(encoded_signature || '')
    end

    # Returns the encoded signature of the JWT token.
    #
    # @return [String] the encoded signature of the JWT token.
    def encoded_signature
      @encoded_signature ||= ::JWT::Base64.url_encode(signature)
    end

    # Returns the decoded header of the JWT token.
    #
    # @return [Hash] the header of the JWT token.
    attr_reader :header

    # Returns the encoded header of the JWT token.
    #
    # @return [String] the encoded header of the JWT token.
    def encoded_header
      @encoded_header ||= ::JWT::Base64.url_encode(JWT::JSON.generate(header))
    end

    # Returns the payload of the JWT token.
    #
    # @return [Hash] the payload of the JWT token.
    attr_reader :payload

    # Returns the encoded payload of the JWT token.
    #
    # @return [String] the encoded payload of the JWT token.
    def encoded_payload
      @encoded_payload ||= ::JWT::Base64.url_encode(JWT::JSON.generate(payload))
    end

    # Returns the signing input of the JWT token.
    #
    # @return [String] the signing input of the JWT token.
    def signing_input
      @signing_input ||= [encoded_header, encoded_payload].join('.')
    end

    # Returns the JWT token as a string.
    #
    # @return [String] the JWT token as a string.
    # @raise [JWT::EncodeError] if the token is not signed or other encoding issues
    def jwt
      @jwt ||= (@signature && [encoded_header, @detached_payload ? '' : encoded_payload, encoded_signature].join('.')) || raise(::JWT::EncodeError, 'Token is not signed')
    end

    # Detaches the payload according to https://datatracker.ietf.org/doc/html/rfc7515#appendix-F
    #
    def detach_payload!
      @detached_payload = true
      @jwt = nil

      nil
    end

    # Signs the JWT token.
    #
    # @param key [String, JWT::JWK::KeyBase] the key to use for signing.
    # @param algorithm [String, Object] the algorithm to use for signing.
    # @return [void]
    # @raise [JWT::EncodeError] if the token is already signed or other problems when signing
    def sign!(key:, algorithm:)
      raise ::JWT::EncodeError, 'Token already signed' if @signature

      JWA.create_signer(algorithm: algorithm, key: key).tap do |signer|
        header.merge!(signer.jwa.header) { |_key, old, _new| old }
        @signature = signer.sign(data: signing_input)
      end

      nil
    end

    # Prepares a two-phase signing request for an external signer (e.g. an
    # offline HSM). The private key is not needed here; the returned
    # {SigningRequest} is serializable and fixes the algorithm, header, payload
    # and the exact bytes to sign.
    #
    # @param algorithm [String, JWT::JWA::SigningAlgorithm] the algorithm to sign with.
    # @return [SigningRequest] the serializable signing request.
    # @raise [JWT::EncodeError] if the token is already signed or the algorithm does not support external signing.
    #
    # @example
    #   token   = JWT::Token.new(payload: {pay: 'load'})
    #   request = token.prepare_signing(algorithm: 'PS256')
    #   # ... external system signs request.signing_input ...
    #   token.finalize_signing!(request, signature: sig, public_key: pubkey)
    def prepare_signing(algorithm:)
      raise ::JWT::EncodeError, 'Token already signed' if @signature

      verify_claims!(:numeric)

      jwa = SigningRequest.resolve_external_algorithm(algorithm)
      header.merge!(jwa.header) { |_key, old, _new| old }

      SigningRequest.new(algorithm: jwa.alg, encoded_header: encoded_header, encoded_payload: encoded_payload)
    end

    # Finalizes a two-phase signing by verifying the externally produced
    # signature against the provided public key and attaching it to the token.
    #
    # @param request [SigningRequest] the request previously prepared with {#prepare_signing}.
    # @param signature [String] the raw or Base64 encoded signature returned by the signer.
    # @param public_key [OpenSSL::PKey::RSA, OpenSSL::PKey::EC, JWT::JWK::KeyBase] the key to verify with.
    # @return [void]
    # @raise [JWT::EncodeError] if the token is already signed.
    # @raise [JWT::VerificationError] if the signature, algorithm or request does not match.
    def finalize_signing!(request, signature:, public_key:)
      raise ::JWT::EncodeError, 'Token already signed' if @signature

      unless request.is_a?(SigningRequest) && request.signing_input == signing_input
        raise ::JWT::VerificationError, 'The signing request does not match the token'
      end

      @signature = request.verify_signature(signature, public_key)

      nil
    end

    # Verifies the claims of the token.
    # @param options [Array<Symbol>, Hash] the claims to verify.
    # @raise [JWT::ClaimValidationError] if the claims are invalid.
    def verify_claims!(*options)
      Claims::Verifier.verify!(self, *options)
    end

    # Returns the errors of the claims of the token.
    # @param options [Array<Symbol>, Hash] the claims to verify.
    # @return [Array<Symbol>] the errors of the claims.
    def claim_errors(*options)
      Claims::Verifier.errors(self, *options)
    end

    # Returns whether the claims of the token are valid.
    # @param options [Array<Symbol>, Hash] the claims to verify.
    # @return [Boolean] whether the claims are valid.
    def valid_claims?(*options)
      claim_errors(*options).empty?
    end

    # Returns the JWT token as a string.
    #
    # @return [String] the JWT token as a string.
    alias to_s jwt
  end
end
