# frozen_string_literal: true

require_relative 'jws/signature'
require_relative 'jws/signer'
require_relative 'jws/policy'
require_relative 'jws/key_identity'
require_relative 'jws/signature_result'
require_relative 'jws/verification_result'
require_relative 'jws/serialized_token'
require_relative 'jws/json_serialization'

module JWT
  # JSON Web Signature (JWS) support, see RFC 7515.
  module JWS
    module_function

    # Produces a JWS General JSON Serialization signed by every given signer.
    #
    # @param payload [Object] the payload shared by all signatures.
    # @param signers [Array<JWT::JWS::Signer, Hash>] one signer per independent key.
    # @return [Hash] the General JSON Serialization structure.
    def general_serialize(payload, signers)
      JsonSerialization.general(payload, signers)
    end

    # Produces a JWS Flattened JSON Serialization signed by one signer.
    #
    # @param payload [Object] the signed payload.
    # @param signer [JWT::JWS::Signer, Hash] the single signer.
    # @return [Hash] the Flattened JSON Serialization structure.
    def flattened_serialize(payload, signer)
      JsonSerialization.flattened(payload, signer)
    end

    # Decodes and verifies a JWS General or Flattened JSON Serialization.
    #
    # Every signature is verified independently and reported in the returned
    # result. The caller supplied policy decides when the token as a whole is
    # considered verified; until then no verified claims are returned.
    #
    # @param json [String, Hash] the General or Flattened serialization.
    # @param algorithms [Array<String, Object>] the algorithm whitelist.
    # @param key [Object, Array, nil] the accepted verification key(s).
    # @param policy [Symbol, Integer, Hash] :all (default) or a distinct-signer threshold.
    # @param critical_headers [Array<String>] critical headers understood by the caller.
    # @param options [Hash] claim verification options.
    # @return [JWT::JWS::VerificationResult]
    def decode(json, algorithms:, key: nil, policy: :all, critical_headers: [], **options, &key_finder)
      JsonSerialization.decode(
        json,
        algorithms: algorithms,
        key: key,
        policy: policy,
        critical_headers: critical_headers,
        **options,
        &key_finder
      )
    end

    # Decodes a JWS JSON Serialization and returns the payload only when the
    # signature policy and the claims are satisfied.
    #
    # @raise [JWT::VerificationError] if the signature policy is not satisfied.
    # @raise [JWT::ClaimValidationError] if the claims are invalid.
    # @return [Object] the verified payload.
    def decode!(json, algorithms:, key: nil, policy: :all, critical_headers: [], **options, &key_finder)
      decode(
        json,
        algorithms: algorithms,
        key: key,
        policy: policy,
        critical_headers: critical_headers,
        **options,
        &key_finder
      ).verified_payload
    end
  end
end
