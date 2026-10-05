# frozen_string_literal: true

require_relative 'oidc/hash_algorithm'
require_relative 'oidc/verifier'

module JWT
  # OpenID Connect ID Token verification on top of the JWS/JWT layer.
  #
  # Verifying the signature and the registered claims of an ID Token is not
  # enough for the hybrid and implicit flows: the token also has to be tied
  # to the authorization response it arrived with. This module verifies the
  # nonce, the authorized party (azp) and the c_hash/at_hash claims that bind
  # the ID Token to the authorization code and access token of the response.
  #
  # @example
  #   id_token = JWT::EncodedToken.new(response.fetch('id_token'))
  #   id_token.verify_signature!(algorithm: 'RS256', key: jwks)
  #
  #   JWT::OIDC::Verifier.new(
  #     response_type: :hybrid,
  #     client_id: 'my-client',
  #     nonce: session.delete(:nonce),
  #     code: response['code'],
  #     access_token: response['access_token']
  #   ).verify!(id_token)
  module OIDC
    # The base class for all OIDC verification errors.
    class Error < JWT::ClaimValidationError; end

    # Raised when the hash algorithm cannot be derived from the verified
    # signature algorithm. An unknown algorithm is never silently mapped to
    # SHA-256.
    class UnsupportedAlgorithmError < JWT::IncorrectAlgorithm; end

    # Raised when the nonce claim is missing or does not match the expected
    # nonce of the authentication request.
    class InvalidNonceError < Error; end

    # Raised when the authorized party (azp) claim is missing for a multi
    # audience token or does not match the client_id.
    class InvalidAuthorizedPartyError < Error; end

    # Raised when a token hash claim (c_hash or at_hash) required by the
    # selected response type scenario is missing from the ID Token.
    class MissingTokenHashError < Error; end

    # Raised when a token hash claim (c_hash or at_hash) does not match the
    # authorization code or access token of the authorization response.
    class InvalidTokenHashError < Error; end
  end
end
