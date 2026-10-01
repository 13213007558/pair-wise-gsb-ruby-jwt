# frozen_string_literal: true

module JWT
  # Low-level JSON Web Signature (JWS) support for signing and verifying
  # raw payload bytes, including unencoded payloads as defined by
  # RFC 7797 (the "b64" header parameter).
  #
  # Unlike the JWT claims API (JWT.encode / JWT.decode), this module never
  # interprets the payload as JSON and never alters the payload bytes:
  # no base64 conversion (when "b64" is false), no newline handling and no
  # encoding conversion is applied. This makes it suitable for signing
  # arbitrary binary content, such as uploaded files, where the caller
  # already holds the original bytes.
  #
  # The detached form (RFC 7515 Appendix F) omits the payload from the
  # compact serialization and is the primary form for unencoded payloads:
  #
  #   jws = JWT::JWS.sign(file_bytes, key, 'HS256', { b64: false }, detached: true)
  #   JWT::JWS.verify(jws, key, 'HS256', payload: file_bytes) # => file_bytes
  module JWS
    module_function

    # Signs raw payload bytes and returns the compact JWS serialization.
    #
    # @param payload [String] the raw payload bytes. An empty string is a
    #   valid, explicitly empty payload.
    # @param key [String, JWT::JWK::KeyBase] the key to sign with.
    # @param algorithm [String, Object] the algorithm to sign with.
    # @param headers [Hash] additional JWS header parameters. Pass
    #   `b64: false` to sign the payload bytes as-is (RFC 7797); the "crit"
    #   header is then automatically extended with "b64".
    # @param detached [Boolean] when true, the payload is omitted from the
    #   compact serialization and must be provided separately for verification.
    # @return [String] the compact JWS serialization.
    # @raise [ArgumentError] if the payload is not a String.
    # @raise [JWT::EncodeError] if an unencoded payload containing a period
    #   (".") is embedded in the compact serialization (RFC 7797 Section 8).
    def sign(payload, key, algorithm = 'HS256', headers = {}, detached: false)
      raise ArgumentError, 'Payload must be a String' unless payload.is_a?(String)

      header = headers.transform_keys(&:to_s)
      unencoded = header['b64'] == false

      if unencoded
        header['crit'] = (Array(header['crit']) | ['b64'])
        if !detached && payload.include?('.')
          raise EncodeError, 'Unencoded payload (b64=false) containing a period (".") cannot be embedded in the compact serialization'
        end
      end

      signer = JWA.create_signer(algorithm: algorithm, key: key)
      header.merge!(signer.jwa.header) { |_key, old, _new| old }

      encoded_header = Base64.url_encode(JSON.generate(header))
      payload_segment = unencoded ? payload.b : Base64.url_encode(payload)
      signing_input = encoded_header.b << '.' << payload_segment
      encoded_signature = Base64.url_encode(signer.sign(data: signing_input))

      compact(encoded_header, detached ? '' : payload_segment, encoded_signature)
    end

    # Verifies a compact JWS and returns the raw payload bytes.
    #
    # The payload bytes are used exactly as provided by the caller: no
    # newline handling or encoding conversion is applied. Changing a single
    # byte of the payload makes the signature verification fail.
    #
    # @param jws [String] the compact JWS serialization.
    # @param key [String, JWT::JWK::KeyBase] the key to verify with.
    # @param algorithms [String, Array<String>, Object] the allowed algorithm(s).
    # @param payload [String, nil] the detached payload bytes. Required when
    #   the payload is not embedded in the compact serialization. An empty
    #   string is a valid, explicitly empty payload and is distinct from
    #   not providing a payload at all (nil).
    # @return [String] the raw payload bytes.
    # @raise [JWT::MalformedTokenError] if the serialization is malformed or
    #   the detached payload is missing.
    # @raise [JWT::InvalidCritError] if "b64" is false but the "crit" header
    #   does not list "b64".
    # @raise [JWT::IncorrectAlgorithm] if the token algorithm is not allowed.
    # @raise [JWT::VerificationError] if the signature does not match.
    def verify(jws, key, algorithms, payload: nil)
      raise ArgumentError, 'Provided JWS must be a String' unless jws.is_a?(String)
      raise MalformedTokenError, 'Not enough or too many segments' unless jws.count('.') == 2

      encoded_header, embedded_payload, encoded_signature = jws.split('.', -1)
      header = parse_header(encoded_header)
      unencoded = header['b64'] == false

      verify_crit!(header) if unencoded

      payload_segment = resolve_payload_segment(embedded_payload, unencoded, payload)
      signing_input = encoded_header.b << '.' << payload_segment

      verify_signature!(key, algorithms, header, signing_input, encoded_signature)

      unencoded ? payload_segment : Base64.url_decode(payload_segment)
    end

    # @api private
    def compact(encoded_header, payload_segment, encoded_signature)
      encoded_header.b << '.' << payload_segment << '.' << encoded_signature
    end
    private_class_method :compact

    # @api private
    def parse_header(encoded_header)
      header = JSON.parse(Base64.url_decode(encoded_header || ''))
      raise MalformedTokenError, 'Token header not a JSON object' unless header.is_a?(Hash)

      header
    rescue ::JSON::ParserError
      raise MalformedTokenError, 'Invalid segment encoding'
    end
    private_class_method :parse_header

    # @api private
    def verify_crit!(header)
      crit = header['crit']
      return if crit.is_a?(Array) && crit.include?('b64')

      raise InvalidCritError, 'Crit header missing expected values: b64'
    end
    private_class_method :verify_crit!

    # @api private
    def resolve_payload_segment(embedded_payload, unencoded, payload)
      if embedded_payload && !embedded_payload.empty?
        raise ArgumentError, 'Payload given both embedded in the token and as an argument' unless payload.nil?

        return unencoded ? embedded_payload.b : embedded_payload
      end

      raise MalformedTokenError, 'Detached payload not provided' if payload.nil?
      raise ArgumentError, 'Payload must be a String' unless payload.is_a?(String)

      unencoded ? payload.b : Base64.url_encode(payload)
    end
    private_class_method :resolve_payload_segment

    # @api private
    def verify_signature!(key, algorithms, header, signing_input, encoded_signature)
      verifiers = JWA.create_verifiers(algorithms: algorithms, keys: Array(key), preferred_algorithm: header['alg'])
      unless verifiers.any? { |verifier| (verifier.respond_to?(:jwa) ? verifier.jwa : verifier).valid_alg?(header['alg']) }
        raise IncorrectAlgorithm, 'Expected a different algorithm'
      end

      signature = Base64.url_decode(encoded_signature || '')
      return if verifiers.any? { |verifier| verifier.verify(data: signing_input, signature: signature) }

      raise VerificationError, 'Signature verification failed'
    end
    private_class_method :verify_signature!
  end
end
