# frozen_string_literal: true

require 'openssl'

require_relative 'jwe/key_management'
require_relative 'jwe/content_encryption'

module JWT
  # JSON Web Encryption (JWE) compact serialization (RFC 7516).
  #
  # Supported key management algorithms: +dir+ and +RSA-OAEP-256+.
  # Supported content encryption algorithms: +A128GCM+ and +A256GCM+.
  #
  # Decryption requires the caller to explicitly allow the key management
  # algorithms and content encryption algorithms. Values found in the token
  # header (+alg+, +enc+, +cty+) only select between the allowed algorithms
  # and never widen the caller's policy.
  #
  # @example Encrypt and decrypt using a shared key ("dir")
  #   cek = SecureRandom.bytes(32)
  #   token = JWT::JWE.encrypt({ 'sub' => 'alice' }, cek, algorithm: 'dir', encryption: 'A256GCM')
  #   payload, header = JWT::JWE.decrypt(token, cek, algorithms: ['dir'], encryptions: ['A256GCM'])
  #
  # @example Nested JWS (signed, then encrypted)
  #   jws = JWT.encode({ 'sub' => 'alice' }, 'secret', 'HS256')
  #   token = JWT::JWE.encrypt(jws, rsa_public, algorithm: 'RSA-OAEP-256', encryption: 'A128GCM', headers: { 'cty' => 'JWT' })
  #   payload, = JWT::JWE.decrypt(token, rsa_private,
  #                               algorithms: ['RSA-OAEP-256'], encryptions: ['A128GCM'],
  #                               jws: { key: 'secret', algorithms: ['HS256'] })
  module JWE
    SEGMENT_COUNT = 5

    private_constant :SEGMENT_COUNT

    class << self
      # Encrypts a payload into a JWE compact serialization.
      #
      # @param payload [Hash, String] the payload. A String is encrypted as-is
      #   (for example a nested signed JWT), a Hash is serialized as JSON.
      # @param key [String, OpenSSL::PKey::RSA] the encryption key. For "dir" the
      #   CEK itself, for "RSA-OAEP-256" the recipient's RSA public key.
      # @param algorithm [String] the key management algorithm ("dir", "RSA-OAEP-256").
      # @param encryption [String] the content encryption algorithm ("A128GCM", "A256GCM").
      # @param headers [Hash] additional protected header fields. The +alg+ and
      #   +enc+ values are always taken from the explicit arguments.
      # @return [String] the JWE compact serialization.
      def encrypt(payload, key, algorithm:, encryption:, headers: {})
        key_management = resolve!(KeyManagement, algorithm, 'alg')
        content_encryption = resolve!(ContentEncryption, encryption, 'enc')

        header = headers.transform_keys(&:to_s).merge('alg' => key_management.alg, 'enc' => content_encryption.alg)
        encoded_header = ::JWT::Base64.url_encode(::JWT::JSON.generate(header))

        cek, encrypted_key = key_management.wrap(key, content_encryption.cek_length)
        iv, ciphertext, tag = content_encryption.encrypt(cek: cek, plaintext: plaintext(payload), aad: encoded_header)

        [encoded_header, *[encrypted_key, iv, ciphertext, tag].map { |part| ::JWT::Base64.url_encode(part) }].join('.')
      end

      # Decrypts a JWE compact serialization.
      #
      # The plaintext claims are not parsed or exposed before the
      # authentication tag has been verified.
      #
      # @param jwe [String] the JWE compact serialization.
      # @param key [String, OpenSSL::PKey::RSA] the decryption key. For "dir" the
      #   CEK itself, for "RSA-OAEP-256" the recipient's RSA private key.
      # @param algorithms [Array<String>] explicitly allowed key management algorithms.
      # @param encryptions [Array<String>] explicitly allowed content encryption algorithms.
      # @param jws [Hash, nil] signature verification policy for a nested JWS
      #   (required when the token carries "cty":"JWT"). Accepts a +:key+ entry,
      #   the remaining entries are passed to {JWT.decode} as options.
      # @return [Array(Hash, Hash)] the decrypted payload and the protected header.
      def decrypt(jwe, key = nil, algorithms: nil, encryptions: nil, jws: nil)
        allowed_algorithms = require_allowlist!(algorithms, 'algorithms')
        allowed_encryptions = require_allowlist!(encryptions, 'encryptions')

        encoded_header, encoded_encrypted_key, encoded_iv, encoded_ciphertext, encoded_tag = segments(jwe)
        header = parse_header(encoded_header)

        key_management = allowed_algorithm!(KeyManagement, allowed_algorithms, header['alg'], 'alg')
        content_encryption = allowed_algorithm!(ContentEncryption, allowed_encryptions, header['enc'], 'enc')
        reject_unsupported_headers!(header)

        plaintext = decrypt_segments(key_management, content_encryption, key,
                                     encoded_header, encoded_encrypted_key, encoded_iv, encoded_ciphertext, encoded_tag)

        [payload(plaintext, header, jws), header]
      end

      private

      def plaintext(payload)
        payload.is_a?(String) ? payload : ::JWT::JSON.generate(payload)
      end

      def payload(plaintext, header, jws_options)
        return verify_nested_jws(plaintext, jws_options) if header['cty'].is_a?(String) && header['cty'].casecmp('JWT').zero?

        ::JWT::JSON.parse(plaintext)
      rescue ::JSON::ParserError
        raise ::JWT::MalformedTokenError, 'Invalid payload encoding'
      end

      def verify_nested_jws(plaintext, jws_options)
        unless jws_options.is_a?(Hash)
          raise ::JWT::JWEError, 'Nested JWS requires an explicit signature verification policy (jws:)'
        end

        options = jws_options.dup
        key = options.delete(:key)
        algorithms = options.delete(:algorithms) || options.delete('algorithms') ||
                     options.delete(:algorithm) || options.delete('algorithm')
        if algorithms.nil? || Array(algorithms).empty?
          raise ::JWT::JWEError, 'Nested JWS requires explicitly allowed signature algorithms'
        end

        ::JWT.decode(plaintext, key, true, options.merge(algorithms: algorithms)).first
      end

      def segments(jwe)
        raise ::JWT::MalformedTokenError, 'Nil JSON web encryption' unless jwe

        segments = jwe.to_s.split('.', -1)
        raise ::JWT::MalformedTokenError, 'Not enough or too many segments' unless segments.size == SEGMENT_COUNT

        segments
      end

      def parse_header(encoded_header)
        header = ::JWT::JSON.parse(::JWT::Base64.url_decode(encoded_header))
        raise ::JWT::MalformedTokenError, 'Token header not a JSON object' unless header.is_a?(Hash)

        header
      rescue ::JSON::ParserError
        raise ::JWT::MalformedTokenError, 'Invalid segment encoding'
      end

      def reject_unsupported_headers!(header)
        raise ::JWT::JWEError, 'Unsupported zip header' if header.key?('zip')
        raise ::JWT::JWEError, 'Unsupported crit header' if header.key?('crit') && header['crit'] != []
      end

      def decrypt_segments(key_management, content_encryption, key, encoded_header, encoded_encrypted_key, encoded_iv, encoded_ciphertext, encoded_tag)
        cek = key_management.unwrap(::JWT::Base64.url_decode(encoded_encrypted_key), key, content_encryption.cek_length)
        content_encryption.decrypt(cek: cek,
                                   iv: ::JWT::Base64.url_decode(encoded_iv),
                                   ciphertext: ::JWT::Base64.url_decode(encoded_ciphertext),
                                   tag: ::JWT::Base64.url_decode(encoded_tag),
                                   aad: encoded_header)
      end

      def require_allowlist!(values, name)
        values = Array(values)
        raise ArgumentError, "Allowed #{name} must be explicitly provided" if values.empty?

        values.map(&:to_s)
      end

      def allowed_algorithm!(registry, allowed, header_value, header_name)
        raise ::JWT::JWEError, "Token is missing #{header_name} header" unless header_value

        algorithm = allowed.include?(header_value) && registry.find(header_value)
        raise ::JWT::JWEError, "Token #{header_name} header is not in the allowed algorithms" unless algorithm

        algorithm
      end

      def resolve!(registry, name, header_name)
        registry.find(name.to_s) || raise(::JWT::JWEError, "Unsupported #{header_name} algorithm: #{name}")
      end
    end
  end
end
