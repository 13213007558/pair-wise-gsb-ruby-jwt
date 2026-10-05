# frozen_string_literal: true

module JWT
  module OIDC
    # Verifies that an ID Token corresponds to the authorization response it
    # was returned with, according to the selected response type scenario.
    #
    # The scenarios follow OpenID Connect Core 1.0:
    #
    # - +:code+ (Authorization Code Flow): the nonce is only verified when one
    #   was sent with the authentication request. The c_hash and at_hash
    #   claims are optional and verified when present.
    # - +:implicit+ (Implicit Flow): the nonce is required. The at_hash claim
    #   is required when the response contains an access token.
    # - +:hybrid+ (Hybrid Flow): the nonce is required. The c_hash claim is
    #   required when the response contains an authorization code and the
    #   at_hash claim is required when the response contains an access token.
    #
    # In all scenarios the authorized party (azp) claim is required to be
    # present and equal to the client_id when the aud claim contains multiple
    # audiences, and a present azp always has to match the client_id.
    class Verifier
      # The supported response type scenarios.
      RESPONSE_TYPES = %i[code implicit hybrid].freeze

      # Initializes a new Verifier instance.
      #
      # @param response_type [Symbol] one of +:code+, +:implicit+ or +:hybrid+.
      # @param client_id [String] the client_id of the relying party.
      # @param nonce [String, nil] the nonce sent with the authentication request.
      #   Required for the +:implicit+ and +:hybrid+ scenarios.
      # @param code [String, nil] the authorization code of the authorization response.
      # @param access_token [String, nil] the access token of the authorization response.
      # @raise [ArgumentError] if the response type is not supported or the
      #   scenario requires a nonce that was not provided.
      def initialize(response_type:, client_id:, nonce: nil, code: nil, access_token: nil)
        @response_type = response_type.to_sym
        raise ArgumentError, "Unsupported response_type: #{response_type.inspect}" unless RESPONSE_TYPES.include?(@response_type)
        raise ArgumentError, 'The client_id is required' if client_id.nil?
        raise ArgumentError, "A nonce is required for the #{response_type} response type" if nonce.nil? && nonce_required?

        @client_id = client_id
        @nonce = nonce
        @code = code
        @access_token = access_token
      end

      # Verifies the ID Token against the authorization response.
      #
      # @param token [JWT::EncodedToken, Hash] the ID Token, either as an
      #   encoded token (whose signature has already been verified) or as a
      #   payload Hash.
      # @param algorithm [String, nil] the verified JWS "alg" header value.
      #   Required when the token is given as a payload Hash, otherwise taken
      #   from the token header.
      # @return [true] when the token corresponds to the authorization response.
      # @raise [JWT::OIDC::Error] if the token does not correspond to the response.
      def verify!(token, algorithm: nil)
        payload, alg = payload_and_algorithm(token, algorithm)

        verify_nonce!(payload)
        verify_authorized_party!(payload)
        verify_token_hash!(payload, claim: 'c_hash', value: code, algorithm: alg, required: c_hash_required?)
        verify_token_hash!(payload, claim: 'at_hash', value: access_token, algorithm: alg, required: at_hash_required?)
        true
      end

      private

      attr_reader :response_type, :client_id, :nonce, :code, :access_token

      def payload_and_algorithm(token, algorithm)
        return [token.unverified_payload, token.header['alg']] if token.is_a?(::JWT::EncodedToken)

        raise ArgumentError, 'The verified signature algorithm is required when the token is given as a payload Hash' if algorithm.nil?

        [token, algorithm]
      end

      def nonce_required?
        response_type != :code
      end

      def c_hash_required?
        response_type == :hybrid && !code.nil?
      end

      def at_hash_required?
        response_type != :code && !access_token.nil?
      end

      def verify_nonce!(payload)
        return if nonce.nil?

        claim = payload['nonce']
        raise InvalidNonceError, 'ID Token is missing the nonce claim' if claim.nil?
        raise InvalidNonceError, 'ID Token nonce does not match the expected nonce' unless secure_compare(claim, nonce)
      end

      def verify_authorized_party!(payload)
        aud = payload['aud']
        azp = payload['azp']

        if aud.is_a?(Array) && aud.size > 1 && azp.nil?
          raise InvalidAuthorizedPartyError, 'ID Token is missing the azp claim required for multiple audiences'
        end

        return if azp.nil? || azp == client_id

        raise InvalidAuthorizedPartyError, "ID Token azp #{azp.inspect} does not match the client_id #{client_id.inspect}"
      end

      def verify_token_hash!(payload, claim:, value:, algorithm:, required:)
        hash = payload[claim]

        if hash.nil?
          raise MissingTokenHashError, "ID Token is missing the #{claim} claim required for the #{response_type} response type" if required

          return
        end

        raise ArgumentError, "Cannot verify the #{claim} claim without the corresponding value" if value.nil?

        expected = HashAlgorithm.hash_token(algorithm, value)
        return if secure_compare(expected, hash)

        raise InvalidTokenHashError, "ID Token #{claim} does not match"
      end

      def secure_compare(first, second)
        ::JWT::JWA::Hmac::SecurityUtils.secure_compare(first.to_s, second.to_s)
      end
    end
  end
end
