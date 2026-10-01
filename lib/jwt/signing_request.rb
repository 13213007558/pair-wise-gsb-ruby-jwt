# frozen_string_literal: true

require 'base64'
require_relative 'jwa'

module JWT
  # A serializable signing request for two-phase (prepare/finalize) signing.
  #
  # The signing key does not need to be available when the token is prepared.
  # The request carries the fixed algorithm, encoded header and payload and the
  # exact bytes that the external signer (e.g. an offline HSM or an approval
  # workflow) has to sign. Once the signature is returned, it can be verified
  # against a public key and combined into the final token with {.finalize} or
  # {#finalize}.
  #
  # Only asymmetric algorithms (RS*, PS* and ES*) are supported, since the
  # private key used for signing is expected to live outside of this library.
  #
  # @example prepare, sign externally and finalize
  #   request = JWT::SigningRequest.prepare(
  #     payload: { data: 'value' },
  #     algorithm: 'ES256',
  #     headers: { kid: 'hsm-key-1' }
  #   )
  #
  #   json = request.to_json # sent to the external signing system
  #
  #   # ... elsewhere, signature bytes come back from the signer ...
  #
  #   token = JWT::SigningRequest.finalize(
  #     json,
  #     signature: external_signature,
  #     public_key: verification_key
  #   )
  #   token.jwt
  class SigningRequest
    # Algorithms whose private key can live outside of the library.
    EXTERNAL_SIGNABLE_ALGORITHMS = %w[RS256 RS384 RS512 PS256 PS384 PS512 ES256 ES256K ES384 ES512].freeze

    # Expected raw (R || S) signature length in bytes per ECDSA algorithm.
    ECDSA_SIGNATURE_LENGTH = {
      'ES256' => 64,
      'ES256K' => 64,
      'ES384' => 96,
      'ES512' => 132
    }.freeze

    private_constant(:EXTERNAL_SIGNABLE_ALGORITHMS, :ECDSA_SIGNATURE_LENGTH)

    # @return [String] the JWA algorithm name, e.g. +'PS256'+.
    attr_reader :algorithm

    # @return [String] the Base64url encoded JWT header (the JWS protected header).
    attr_reader :encoded_header

    # @return [String] the Base64url encoded JWT payload.
    attr_reader :encoded_payload

    # Prepares a serializable signing request.
    #
    # @param payload [Hash] the payload of the JWT token.
    # @param algorithm [String, JWT::JWA::SigningAlgorithm] the algorithm to sign with.
    # @param headers [Hash] additional headers to include in the JWT.
    # @param public_key [OpenSSL::PKey::RSA, OpenSSL::PKey::EC, JWT::JWK::KeyBase, nil]
    #   optional public key used to check that the algorithm is usable with the key.
    # @return [SigningRequest]
    # @raise [JWT::EncodeError] if the algorithm cannot be used for external signing.
    def self.prepare(payload:, algorithm:, headers: {}, public_key: nil)
      jwa = resolve_external_algorithm(algorithm)
      validate_public_key_algorithm!(jwa, public_key) if public_key

      token = Token.new(payload: payload, header: headers.merge(jwa.header) { |_key, old, _new| old })
      token.verify_claims!(:numeric)

      new(algorithm: jwa.alg, encoded_header: token.encoded_header, encoded_payload: token.encoded_payload)
    end

    # Reads a signing request from a Hash (e.g. a parsed JSON document).
    #
    # @param hash [Hash] the serialized request.
    # @return [SigningRequest]
    # @raise [JWT::MalformedTokenError] if the hash is not a valid request.
    def self.from_h(hash)
      unless hash.is_a?(Hash)
        raise MalformedTokenError, 'The signing request must be a JSON object'
      end

      hash = hash.transform_keys(&:to_s)

      if hash['alg'].nil? || hash['protected'].nil? || hash['payload'].nil?
        raise MalformedTokenError, 'The signing request is missing one of the alg, protected or payload fields'
      end

      new(
        algorithm: hash['alg'],
        encoded_header: hash['protected'],
        encoded_payload: hash['payload'],
        signing_input: hash['signing_input']
      )
    end

    # Reads a signing request from a JSON String.
    #
    # @param json [String] the serialized request.
    # @return [SigningRequest]
    def self.from_json(json)
      from_h(::JSON.parse(json))
    rescue ::JSON::ParserError
      raise MalformedTokenError, 'Invalid signing request encoding'
    end

    # Verifies an externally produced signature and builds the signed token.
    #
    # Accepts a {SigningRequest}, a Hash or a JSON String as the request.
    #
    # @param request [SigningRequest, Hash, String] the prepared signing request.
    # @param signature [String] the raw or Base64 encoded signature returned by the signer.
    # @param public_key [OpenSSL::PKey::RSA, OpenSSL::PKey::EC, JWT::JWK::KeyBase] the key to verify with.
    # @return [JWT::Token] the finalized, signed token.
    # @raise [JWT::VerificationError] if the signature is invalid or belongs to another request.
    # @raise [JWT::VerificationKeyError] if the public key or algorithm cannot be used.
    def self.finalize(request, signature:, public_key:)
      request = from_json(request) if request.is_a?(String)
      request = from_h(request) if request.is_a?(Hash)
      unless request.is_a?(SigningRequest)
        raise ArgumentError, 'Request must be a SigningRequest, Hash or JSON String'
      end

      request.finalize(signature: signature, public_key: public_key)
    end

    # @param algorithm [String, JWT::JWA::SigningAlgorithm] the JWA algorithm name.
    # @param encoded_header [String] the Base64url encoded header.
    # @param encoded_payload [String] the Base64url encoded payload.
    # @param signing_input [String, nil] optional signing input cross-checked against the segments.
    # @raise [JWT::MalformedTokenError] if the request is internally inconsistent.
    def initialize(algorithm:, encoded_header:, encoded_payload:, signing_input: nil)
      @jwa = self.class.resolve_external_algorithm(algorithm)
      @algorithm = @jwa.alg
      @encoded_header = encoded_header.to_s
      @encoded_payload = encoded_payload.to_s

      validate_segments!(signing_input)
    end

    # @return [String] the exact bytes to be signed: +encoded_header + '.' + encoded_payload+.
    def signing_input
      @signing_input ||= [encoded_header, encoded_payload].join('.')
    end

    # @return [Hash] a JSON serializable representation of the request.
    def to_h
      {
        'alg' => algorithm,
        'protected' => encoded_header,
        'payload' => encoded_payload,
        'signing_input' => signing_input
      }
    end

    # @param args [Array] arguments passed on to +JSON.generate+ (e.g. state).
    # @return [String] a JSON String representation of the request.
    def to_json(*args)
      ::JWT::JSON.generate(to_h, *args)
    end

    # @return [Hash] the decoded JWT header.
    def header
      @header ||= parse_segment(encoded_header)
    end

    # @return [Hash] the decoded JWT payload.
    def payload
      @payload ||= parse_segment(encoded_payload)
    end

    # Verifies the returned signature and builds the finalized token.
    #
    # @param signature [String] the raw or Base64 encoded signature returned by the signer.
    # @param public_key [OpenSSL::PKey::RSA, OpenSSL::PKey::EC, JWT::JWK::KeyBase] the key to verify with.
    # @return [JWT::Token] the finalized, signed token.
    # @raise [JWT::VerificationError] if the signature is invalid or belongs to another request.
    def finalize(signature:, public_key:)
      raw_signature = verify_signature(signature, public_key)

      Token.from_encoded_segments(
        encoded_header: encoded_header,
        encoded_payload: encoded_payload,
        signature: raw_signature
      )
    end

    # Tries the signature in every encoding the external signer might have used
    # and returns the raw JOSE signature bytes once one of them verifies.
    #
    # @param signature [String] the raw or Base64 encoded signature returned by the signer.
    # @param public_key [OpenSSL::PKey::RSA, OpenSSL::PKey::EC, JWT::JWK::KeyBase] the key to verify with.
    # @return [String] the normalized raw JOSE signature.
    # @raise [JWT::VerificationError] if the signature is invalid or belongs to another request.
    # @api private
    def verify_signature(signature, public_key)
      candidates = signature_candidates(signature)

      candidates.each do |candidate|
        return candidate if verifies?(public_key, candidate)
      end

      raise VerificationError, 'Signature verification failed'
    end

    class << self
      # Resolves an algorithm and checks that it can be used with an external
      # (asymmetric) signer.
      #
      # @return [JWT::JWA::SigningAlgorithm]
      # @raise [JWT::EncodeError] if the algorithm is unsupported or symmetric.
      # @api private
      def resolve_external_algorithm(algorithm)
        jwa = JWA.resolve(algorithm)
        return jwa if jwa.is_a?(JWA::SigningAlgorithm) && EXTERNAL_SIGNABLE_ALGORITHMS.include?(jwa.alg)

        supported = EXTERNAL_SIGNABLE_ALGORITHMS.join(', ')
        raise EncodeError, "External signing is only supported for asymmetric algorithms: #{supported}"
      end

      private

      # @api private
      def validate_public_key_algorithm!(jwa, public_key)
        jwk_key = public_key.is_a?(JWK::KeyBase) ? public_key.verify_key : public_key
        expected = expected_key_class(jwa.alg)

        return if expected.nil?
        return if jwk_key.is_a?(expected)

        raise VerificationKeyError, "A #{jwa.alg} request requires a #{expected} verification key"
      end

      # @api private
      def expected_key_class(alg)
        case alg
        when /\A(RS|PS)/ then OpenSSL::PKey::RSA
        when /\AES/ then OpenSSL::PKey::EC
        end
      end
    end

    private

    def verifies?(public_key, signature)
      verifiers = JWA.create_verifiers(algorithms: algorithm, keys: [public_key], preferred_algorithm: algorithm)
      verifiers.any? { |verifier| verifier.verify(data: signing_input, signature: signature) }
    rescue VerificationKeyError, IncorrectAlgorithm
      raise
    rescue StandardError
      false
    end

    def signature_candidates(signature)
      unless signature.is_a?(String) && !signature.empty?
        error = VerificationError.new('The returned signature must be a non empty String')
        error.set_backtrace(caller(1))
        raise error
      end

      candidates = [signature]
      decoded = loose_base64_decode(signature)
      candidates << decoded if decoded

      candidates.flat_map { |candidate| expand_ecdsa_der(candidate) }.uniq
    end

    # ECDSA signers outside of the library commonly return the DER encoded
    # (r, s) structure while JOSE uses fixed length raw R || S bytes. Both are
    # accepted and normalized here.
    def expand_ecdsa_der(signature)
      expected_length = ECDSA_SIGNATURE_LENGTH[algorithm]
      return [signature] unless expected_length

      raw = ecdsa_der_to_raw(signature, expected_length)
      (raw && raw != signature) ? [raw, signature] : [signature]
    end

    # Converts an ECDSA signature in DER (r, s) encoding to the fixed length
    # raw R || S encoding used by JOSE. Returns nil when the input is not a
    # valid DER signature of the expected length.
    def ecdsa_der_to_raw(signature, expected_length)
      asn1 = OpenSSL::ASN1.decode(signature)
      return nil unless asn1.is_a?(OpenSSL::ASN1::Sequence) && asn1.value.length == 2

      half = expected_length / 2
      parts = asn1.value.map do |part|
        return nil unless part.is_a?(OpenSSL::ASN1::Integer)

        bytes = part.value.to_s(2)
        return nil if bytes.bytesize > half

        bytes.rjust(half, "\x00")
      end

      parts.join
    rescue StandardError
      nil
    end

    def loose_base64_decode(signature)
      ::Base64.urlsafe_decode64(signature)
    rescue ArgumentError
      begin
        ::Base64.strict_decode64(signature)
      rescue ArgumentError
        nil
      end
    end

    def parse_segment(segment)
      ::JWT::JSON.parse(::JWT::Base64.url_decode(segment))
    rescue ::JSON::ParserError, Base64DecodeError
      raise MalformedTokenError, 'Invalid signing request segment encoding'
    end

    def validate_segments!(signing_input)
      unless header.is_a?(Hash)
        raise MalformedTokenError, 'The signing request header must be a JSON object'
      end

      unless @jwa.valid_alg?(header['alg'])
        raise MalformedTokenError, "The protected header alg '#{header['alg']}' does not match the request algorithm '#{algorithm}'"
      end

      return if signing_input.nil? || signing_input == self.signing_input

      raise MalformedTokenError, 'The signing input does not match the encoded header and payload'
    end
  end
end
