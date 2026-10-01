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
  # Unencoded payloads as described by RFC 7797 are supported on this low level
  # interface by setting the 'b64' header to false. The payload bytes are then
  # used verbatim for signing instead of being base64url encoded:
  #   token = JWT::Token.new(payload: "raw\x00bytes", header: {'b64' => false})
  #   token.sign!(algorithm: 'HS256', key: 'secret')
  #   token.detach_payload!
  #   token.jwt # => "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..<signature>"
  #
  class Token
    # Initializes a new Token instance.
    #
    # @param header [Hash] the header of the JWT token.
    # @param payload [Hash, String, Array, Numeric] the payload of the JWT token.
    #   When the header contains `'b64' => false` (RFC 7797) the payload is
    #   expected to be a String with the exact bytes to be signed.
    def initialize(payload:, header: {})
      @header  = header&.transform_keys(&:to_s)
      @payload = payload
    end

    # Tells whether the payload is transported unencoded as described in RFC 7797.
    #
    # @return [Boolean] true when the 'b64' header is explicitly false.
    def unencoded?
      header['b64'] == false
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
    # With an RFC 7797 unencoded payload ('b64' header false) the payload is not
    # base64url encoded. The raw bytes are returned as-is, including non UTF-8
    # bytes. For a detached JWS the same bytes must be supplied again when
    # verifying the signature.
    #
    # @return [String] the encoded payload of the JWT token.
    def encoded_payload
      @encoded_payload ||= unencoded? ? payload.to_s : ::JWT::Base64.url_encode(JWT::JSON.generate(payload))
    end

    # Returns the signing input of the JWT token.
    #
    # For an RFC 7797 unencoded payload the raw payload bytes are used instead
    # of the base64url encoded representation.
    #
    # @return [String] the signing input of the JWT token.
    def signing_input
      @signing_input ||= [encoded_header, encoded_payload].join('.')
    end

    # Returns the JWT token as a string.
    #
    # @return [String] the JWT token as a string.
    # @raise [JWT::EncodeError] if the token is not signed, other encoding issues
    #   or when an unencoded non detached payload contains the '.' character.
    def jwt
      raise(::JWT::EncodeError, 'Token is not signed') unless @signature
      raise(::JWT::EncodeError, "Invalid unencoded payload, '.' character is not allowed in the payload") if inline_unencoded_payload?

      @jwt ||= [encoded_header, @detached_payload ? '' : encoded_payload, encoded_signature].join('.')
    end

    # Detaches the payload according to https://datatracker.ietf.org/doc/html/rfc7515#appendix-F
    #
    # This is also the required representation for unencoded payloads containing
    # bytes (such as '.') that can not be carried in the compact serialization.
    def detach_payload!
      @detached_payload = true
      @jwt = nil

      nil
    end

    # Signs the JWT token.
    #
    # For an RFC 7797 unencoded payload ('b64' header false) the 'b64' entry is
    # automatically added to the 'crit' header.
    #
    # @param key [String, JWT::JWK::KeyBase] the key to use for signing.
    # @param algorithm [String, Object] the algorithm to use for signing.
    # @return [void]
    # @raise [JWT::EncodeError] if the token is already signed or other problems when signing
    def sign!(key:, algorithm:)
      raise ::JWT::EncodeError, 'Token already signed' if @signature

      prepare_unencoded_header!

      JWA.create_signer(algorithm: algorithm, key: key).tap do |signer|
        header.merge!(signer.jwa.header) { |_key, old, _new| old }
        @signature = signer.sign(data: signing_input)
      end

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

    private

    # RFC 7797 section 1: when 'b64' is false the header MUST include 'b64' in
    # the list of headers in 'crit'.
    def prepare_unencoded_header!
      return unless unencoded?

      crit = header['crit']
      raise ::JWT::EncodeError, 'The crit header must be an Array' unless crit.nil? || crit.is_a?(Array)

      header['crit'] = Array(crit) | ['b64']
    end

    def inline_unencoded_payload?
      unencoded? && !@detached_payload && encoded_payload.include?('.')
    end
  end
end
