# frozen_string_literal: true

require_relative 'jws/signature'
require_relative 'jws/policy'
require_relative 'jws/result'
require_relative 'jws/serializer'
require_relative 'jws/verifier'

module JWT
  # JSON Web Signature (JWS) JSON Serialization support, as described in
  # {https://www.rfc-editor.org/rfc/rfc7515#section-7 RFC 7515 section 7}.
  #
  # Unlike compact serialization, a JWS JSON Serialization can carry more than
  # one signature over the same payload. Every signature is verified on its
  # own, and the caller decides through a policy how many independent signers
  # have to be valid.
  module JWS
    module_function

    # Produces a JWS General JSON Serialization.
    #
    # @example sign the same payload with two independent keys
    #   JWT::JWS.sign(
    #     { 'sub' => '42' },
    #     [{ algorithm: 'HS256', key: 'secret-a', kid: 'a' },
    #      { algorithm: 'HS256', key: 'secret-b', kid: 'b' }]
    #   )
    #   # => { "payload" => "...", "signatures" => [...] }
    #
    # @param payload [Object] the payload shared by every signature.
    # @param signers [Array<Hash, JWT::JWS::Signature>] one specification per independent signer.
    # @return [Hash] the JWS General JSON Serialization.
    def sign(payload, signers)
      signatures = Array(signers).map { |spec| spec.is_a?(Signature) ? spec.dup : Signature.from(spec) }
      verify_numeric_claims!(payload)
      Serializer.new(payload, signatures).serialize(flattened: false)
    end

    # Produces a JWS Flattened JSON Serialization containing one signature.
    #
    # @param payload [Object] the payload.
    # @param signer [Hash, JWT::JWS::Signature] the single signer specification.
    # @return [Hash] the JWS Flattened JSON Serialization.
    def sign_flattened(payload, signer)
      signature = signer.is_a?(Signature) ? signer.dup : Signature.from(signer)
      verify_numeric_claims!(payload)
      Serializer.new(payload, [signature]).serialize(flattened: true)
    end

    # Verifies a JWS JSON Serialization without raising on policy failure.
    #
    # @example all named signers must be valid
    #   result = JWT::JWS.verify(
    #     jws,
    #     algorithms: ['HS256'],
    #     signers: [{ algorithm: 'HS256', key: 'secret-a', kid: 'a' },
    #               { algorithm: 'HS256', key: 'secret-b', kid: 'b' }],
    #     policy: :all
    #   )
    #   result.verified?      # => true
    #   result.signatures     # => per-signature results
    #   result.claims         # => the verified payload
    #
    # @example at least two distinct keys must be valid
    #   JWT::JWS.verify(jws, algorithms: ['HS256'], keys: [key_a, key_b], policy: 2)
    #
    # @param jws [Hash, String] the JWS JSON Serialization.
    # @param algorithms [Array<String>] the caller controlled algorithm whitelist. Required.
    # @param keys [Array] fixed verification keys tried for every signature.
    # @param signers [Array<Hash, JWT::JWS::Signature>] key specifications matched by `kid`.
    # @param keyfinder [Proc] block resolving a key from a signature header.
    # @param policy [Symbol, Integer, Hash] :all (default), :any, a count or `{ threshold: n }`.
    # @param options [Hash] claim verification options (see JWT.decode) plus `:crit`.
    # @return [JWT::JWS::VerificationResult]
    def verify(jws, algorithms: nil, keys: nil, signers: nil, keyfinder: nil, policy: nil, **options)
      raise ArgumentError, 'Provide either keys, signers or keyfinder' if [keys, signers, keyfinder].compact.size > 1

      Verifier.new(jws,
                   algorithms: algorithms,
                   keys: keys,
                   signers: signers,
                   keyfinder: keyfinder,
                   policy: policy,
                   **options).verify
    end

    # Verifies a JWS JSON Serialization and returns the claims.
    #
    # @return [Array<Hash>] the decoded payload and the header of a verified signature.
    # @raise [JWT::Error] when the serialization, a signature, the claims or the policy is invalid.
    def decode(jws, algorithms: nil, keys: nil, signers: nil, keyfinder: nil, policy: nil, **options)
      raise ArgumentError, 'Provide either keys, signers or keyfinder' if [keys, signers, keyfinder].compact.size > 1

      Verifier.new(jws,
                   algorithms: algorithms,
                   keys: keys,
                   signers: signers,
                   keyfinder: keyfinder,
                   policy: policy,
                   **options).decode
    end

    # @api private
    def verify_numeric_claims!(payload)
      Token.new(payload: payload).verify_claims!(:numeric)
    end
  end
end
