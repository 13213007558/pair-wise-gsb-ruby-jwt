# frozen_string_literal: true

require_relative '../claims'
require_relative '../json'
require_relative 'policy'
require_relative 'serialized_token'
require_relative 'signer'
require_relative 'verification_result'

module JWT
  module JWS
    # Independent entry point for the JWS General and Flattened JSON
    # Serializations (RFC 7515).
    #
    # Unlike the compact serialization a single payload can be signed by
    # several keys and the caller decides how many of the signatures have to
    # verify before the payload is returned as verified.
    class JsonSerialization
      # Encodes the payload with the given signers using the General JSON Serialization.
      #
      # @param payload [Object] the payload shared by all signatures.
      # @param signers [Array<JWT::JWS::Signer, Hash>] one signer per independent key.
      # @return [Hash] the General JSON Serialization structure.
      def self.general(payload, signers)
        new(payload, signers).general
      end

      # Encodes the payload with one signer using the Flattened JSON Serialization.
      #
      # @param payload [Object] the payload signed by the signer.
      # @param signer [JWT::JWS::Signer, Hash] the single signer.
      # @return [Hash] the Flattened JSON Serialization structure.
      def self.flattened(payload, signer)
        new(payload, [signer]).flattened
      end

      # Decodes and verifies a JSON serialized JWS.
      #
      # @param json [String, Hash] the General or Flattened serialization.
      # @param algorithms [Array<String, Object>] the algorithm whitelist, always provided by the caller.
      # @param key [Object, Array, nil] the accepted verification key(s).
      # @param policy [Symbol, Integer, Hash] :all (default) or a threshold of distinct signers.
      # @param critical_headers [Array<String>] critical headers understood by the caller.
      # @param options [Hash] claim verification options, same as JWT.decode.
      # @param key_finder [#call, nil] resolves the verification key per signature.
      # @return [JWT::JWS::VerificationResult]
      def self.decode(json, algorithms:, key: nil, policy: :all, critical_headers: [], key_finder: nil, **options, &block)
        raise ::JWT::IncorrectAlgorithm, 'An algorithm must be specified' if Array(algorithms).empty?

        token = SerializedToken.parse(json)
        finder = key_finder || block
        results = token.verify_signatures(
          algorithms: algorithms,
          keys: Array(key),
          key_finder: finder,
          known_crit: critical_headers
        )

        built_policy = Policy.build(policy)
        payload = token.unverified_payload
        claims_error = verify_claims(payload, built_policy, results, options)

        VerificationResult.new(
          payload: payload,
          signature_results: results,
          policy: built_policy,
          claims_error: claims_error
        )
      end

      def self.verify_claims(payload, policy, results, options)
        return nil unless policy.satisfied?(results)
        return nil unless payload.is_a?(::Hash)

        Claims::DecodeVerifier.verify!(payload, ::JWT.configuration.decode.to_h.merge(options))
        nil
      rescue ::JWT::ClaimValidationError => e
        e
      end
      private_class_method :verify_claims

      def initialize(payload, signers)
        @signers = Array(signers).map { |signer| signer.is_a?(Signer) ? signer : Signer.new(**signer) }
        @token = Token.new(payload: payload)
        @token.verify_claims!(:numeric)
      end

      # @return [Hash] the General JSON Serialization structure.
      def general
        raise ::JWT::EncodeError, 'General JSON Serialization requires at least one signer' if @signers.empty?

        {
          'payload' => encoded_payload,
          'signatures' => @signers.map { |signer| signer.sign(encoded_payload).to_flattened_hash }
        }
      end

      # @return [Hash] the Flattened JSON Serialization structure.
      def flattened
        raise ::JWT::EncodeError, 'Flattened JSON Serialization requires exactly one signer' unless @signers.size == 1

        { 'payload' => encoded_payload }.merge(@signers.first.sign(encoded_payload).to_flattened_hash)
      end

      private

      def encoded_payload
        @encoded_payload ||= ::JWT::Base64.url_encode(JWT::JSON.generate(@token.payload))
      end
    end
  end
end
