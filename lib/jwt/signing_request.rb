# frozen_string_literal: true

module JWT
  # A SigningRequest is the first phase of a two-phase external signing
  # flow, intended for setups where the private key is not directly
  # accessible (for example an offline HSM or an approval based signing
  # service).
  #
  # The request pins the algorithm, header, payload and the exact bytes to
  # be signed, and can be serialized and handed over to the external
  # signer:
  #
  #   request = JWT.prepare({ 'sub' => '123' }, algorithm: 'PS256', headers: { 'kid' => 'key-1' })
  #   request.signing_input # the exact bytes the external signer must sign
  #   serialized = request.to_json
  #
  # Once the external signer returns a signature, the second phase verifies
  # the signature against the pinned request with the provided public key
  # and produces the token:
  #
  #   request = JWT::SigningRequest.from_json(serialized)
  #   token = JWT.finalize(request, signature, key: public_key)
  class SigningRequest
    class << self
      # Prepares a signing request for external signing.
      #
      # @param payload [Hash] the payload of the JWT token.
      # @param algorithm [String, Object] the algorithm the external signer will use.
      # @param headers [Hash] additional headers for the JWT token.
      # @return [JWT::SigningRequest] the prepared signing request.
      # @raise [JWT::EncodeError] if the algorithm is unsupported or not asymmetric.
      def prepare(payload, algorithm:, headers: {})
        jwa = JWA.resolve(algorithm)
        raise ::JWT::EncodeError, "Unsupported signing algorithm: #{algorithm}" if jwa == JWA::Unsupported
        raise ::JWT::EncodeError, 'External signing requires an asymmetric algorithm' if jwa.is_a?(JWA::Hmac) || jwa.is_a?(JWA::None)

        token = Token.new(payload: payload, header: headers)
        token.verify_claims!(:numeric)
        token.header.merge!(jwa.header) { |_key, old, _new| old }

        new(algorithm: jwa.alg, header: token.header, payload: token.payload)
      end

      # Restores a signing request from a Hash, as produced by {#to_h}.
      #
      # @param hash [Hash] the serialized signing request.
      # @return [JWT::SigningRequest] the restored signing request.
      # @raise [JWT::EncodeError] if the serialized request is inconsistent.
      def from_h(hash)
        request = new(algorithm: hash['algorithm'] || hash[:algorithm],
                      header: hash['header'] || hash[:header] || {},
                      payload: hash['payload'] || hash[:payload] || {})
        pinned = hash['signing_input'] || hash[:signing_input]
        request.send(:pin_signing_input, pinned) if pinned
        request
      end

      # Restores a signing request from a JSON document, as produced by {#to_json}.
      #
      # @param json [String] the serialized signing request.
      # @return [JWT::SigningRequest] the restored signing request.
      def from_json(json)
        from_h(JWT::JSON.parse(json))
      end
    end

    # Initializes a new SigningRequest instance.
    #
    # @param algorithm [String] the pinned algorithm.
    # @param header [Hash] the pinned header of the JWT token.
    # @param payload [Hash] the pinned payload of the JWT token.
    def initialize(algorithm:, header:, payload:)
      @algorithm = algorithm
      @header = header.transform_keys(&:to_s)
      @payload = payload
    end

    # Returns the pinned algorithm of the request.
    #
    # @return [String] the algorithm.
    attr_reader :algorithm

    # Returns the pinned header of the request.
    #
    # @return [Hash] the header.
    attr_reader :header

    # Returns the pinned payload of the request.
    #
    # @return [Hash] the payload.
    attr_reader :payload

    # Returns the exact bytes the external signer is expected to sign.
    #
    # @return [String] the signing input.
    def signing_input
      [encoded_header, encoded_payload].join('.')
    end

    # Returns a serializable representation of the request.
    #
    # @return [Hash] the request as a Hash.
    def to_h
      {
        'algorithm' => algorithm,
        'header' => header,
        'payload' => payload,
        'signing_input' => signing_input
      }
    end

    # Returns a JSON serialization of the request.
    #
    # @return [String] the request as JSON.
    def to_json(*args)
      JWT::JSON.generate(to_h)
    end

    # Finalizes the request with a signature produced by the external
    # signer. The signature is verified against the pinned algorithm,
    # header, payload and signing bytes using the provided public key
    # before the token is assembled.
    #
    # @param signature [String] the signature, in raw, Base64/Base64URL or
    #   (for ECDSA) ASN.1 DER form.
    # @param key [Object] the public key corresponding to the external signer's private key.
    # @return [String] the encoded JWT token.
    # @raise [JWT::VerificationError] if the signature does not match the request.
    # @raise [JWT::VerificationKeyError] if the key does not match the pinned algorithm.
    def finalize(signature, key:)
      jwa = JWA.resolve(algorithm)
      raise ::JWT::EncodeError, "Unsupported signing algorithm: #{algorithm}" if jwa == JWA::Unsupported

      verify_request_integrity!

      normalized = ExternalSignature.normalize(jwa: jwa, signature: signature, verification_key: key)
      unless jwa.verify(data: signing_input, signature: normalized, verification_key: key)
        raise ::JWT::VerificationError, 'Signature does not match the signing request'
      end

      [encoded_header, encoded_payload, ::JWT::Base64.url_encode(normalized)].join('.')
    end

    private

    def encoded_header
      ::JWT::Base64.url_encode(JWT::JSON.generate(header))
    end

    def encoded_payload
      ::JWT::Base64.url_encode(JWT::JSON.generate(payload))
    end

    def pin_signing_input(pinned)
      raise ::JWT::EncodeError, 'Signing request signing_input does not match header and payload' unless pinned == signing_input

      @pinned_signing_input = pinned
    end

    def verify_request_integrity!
      return unless @pinned_signing_input && @pinned_signing_input != signing_input

      raise ::JWT::EncodeError, 'Signing request header or payload was modified after preparation'
    end
  end
end
