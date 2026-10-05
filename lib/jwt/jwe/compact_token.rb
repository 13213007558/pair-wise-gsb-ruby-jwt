# frozen_string_literal: true

require 'openssl'
require 'securerandom'

module JWT
  module JWE
    # Represents a JWE token serialized using the compact serialization
    # defined by RFC 7516.
    class CompactToken
      SEGMENT_COUNT = 5
      KEY_MANAGEMENT_ALGORITHMS = %w[dir RSA-OAEP-256].freeze
      CONTENT_ENCRYPTION_ALGORITHMS = %w[A128GCM A256GCM].freeze

      CIPHERS = {
        'A128GCM' => { cipher: 'aes-128-gcm', key_length: 16 },
        'A256GCM' => { cipher: 'aes-256-gcm', key_length: 32 }
      }.freeze

      attr_reader :jwt

      def initialize(jwt)
        raise ArgumentError, 'Provided JWE must be a String' unless jwt.is_a?(String)

        @jwt = jwt
        @raw_segments = jwt.split('.', SEGMENT_COUNT)
      end

      def encoded_header
        raw_segments.first
      end

      def header
        @header ||= parse_header(encoded_header)
      end

      def encrypted_key
        @encrypted_key ||= decode_segment(raw_segments.at(1))
      end

      def iv
        @iv ||= decode_segment(raw_segments.at(2))
      end

      def ciphertext
        @ciphertext ||= decode_segment(raw_segments.at(3))
      end

      def authentication_tag
        @authentication_tag ||= decode_segment(raw_segments.at(4))
      end

      def decrypt(key:, algorithms:, encryption_algorithms:)
        allowed_algorithms = Array(algorithms).map(&:to_s)
        allowed_encryption_algorithms = Array(encryption_algorithms).map(&:to_s)

        validate_segment_count!
        validate_algorithms!(allowed_algorithms, allowed_encryption_algorithms)
        validate_segments!
        validate_header!
        validate_key!(key)

        content_encryption_key = unwrap_content_encryption_key(key)
        plaintext = decrypt_content(content_encryption_key)
        @plaintext = plaintext
      end

      def plaintext
        raise JWT::DecodeError, 'Verify the JWE authentication tag before accessing the plaintext' unless @plaintext

        @plaintext.dup
      end

      def self.decrypt(jwt, key, algorithms, encryption_algorithms)
        token = new(jwt)
        token.decrypt(key: key, algorithms: algorithms, encryption_algorithms: encryption_algorithms)
        token
      end

      def self.encrypt(plaintext, key:, algorithm:, encryption_algorithm:, iv: nil, **header_fields)
        alg = algorithm.to_s
        enc = encryption_algorithm.to_s
        raise JWT::IncorrectAlgorithm, 'Unsupported key management algorithm' unless KEY_MANAGEMENT_ALGORITHMS.include?(alg)
        raise JWT::IncorrectAlgorithm, 'Unsupported content encryption algorithm' unless CONTENT_ENCRYPTION_ALGORITHMS.include?(enc)

        details = CIPHERS.fetch(enc)
        header = header_fields.merge(alg: alg, enc: enc)
        encoded_header = ::JWT::Base64.url_encode(JWT::JSON.generate(header))
        content_encryption_key, encrypted_key = content_encryption_key_for_encryption(alg, key, details[:key_length])
        iv ||= SecureRandom.random_bytes(12)
        raise JWT::EncodeError, 'Invalid JWE initialization vector length' unless iv.bytesize == 12

        ciphertext, authentication_tag = encrypt_content(details[:cipher], content_encryption_key, iv, plaintext, encoded_header)
        [encoded_header,
         ::JWT::Base64.url_encode(encrypted_key),
         ::JWT::Base64.url_encode(iv),
         ::JWT::Base64.url_encode(ciphertext),
         ::JWT::Base64.url_encode(authentication_tag)].join('.')
      end

      private

      attr_reader :raw_segments

      def parse_header(encoded_header)
        header = JWT::JSON.parse(decode_segment(encoded_header))
        raise JWT::MalformedTokenError, 'JWE header must be a JSON object' unless header.is_a?(Hash)

        header
      rescue ::JSON::ParserError
        raise JWT::MalformedTokenError, 'Invalid JWE header encoding'
      end

      def decode_segment(segment)
        raise JWT::MalformedTokenError, 'Invalid JWE segment encoding' if segment.nil?

        ::JWT::Base64.url_decode(segment)
      end

      def validate_algorithms!(allowed_algorithms, allowed_encryption_algorithms)
        raise JWT::IncorrectAlgorithm, 'A key management algorithm must be specified' if allowed_algorithms.empty?
        raise JWT::IncorrectAlgorithm, 'A content encryption algorithm must be specified' if allowed_encryption_algorithms.empty?
        raise JWT::MalformedTokenError, 'JWE header is missing alg' unless header['alg'].is_a?(String)
        raise JWT::MalformedTokenError, 'JWE header is missing enc' unless header['enc'].is_a?(String)
        raise JWT::IncorrectAlgorithm, 'Expected a different algorithm' unless allowed_algorithms.include?(header['alg'])
        raise JWT::IncorrectAlgorithm, 'Expected a different encryption algorithm' unless allowed_encryption_algorithms.include?(header['enc'])
        raise JWT::IncorrectAlgorithm, 'Unsupported key management algorithm' unless KEY_MANAGEMENT_ALGORITHMS.include?(header['alg'])
        raise JWT::IncorrectAlgorithm, 'Unsupported content encryption algorithm' unless CONTENT_ENCRYPTION_ALGORITHMS.include?(header['enc'])
      end

      def validate_segments!
        validate_segment_count!
        raise JWT::MalformedTokenError, 'Invalid JWE initialization vector' unless iv.bytesize == 12
        raise JWT::MalformedTokenError, 'Invalid JWE authentication tag' unless authentication_tag.bytesize == 16
      end

      def validate_segment_count!
        raise JWT::MalformedTokenError, 'Invalid JWE segment count' unless raw_segments.compact.count == SEGMENT_COUNT
      end

      def validate_key!(key)
        case header['alg']
        when 'dir'
          materialized_key = key_material(key)
          raise JWT::DecodeError, 'No decryption key available' unless valid_direct_key?(materialized_key)
          raise JWT::VerificationError, 'JWE decryption failed' unless encrypted_key.empty?
        when 'RSA-OAEP-256'
          materialized_key = key_material(key)
          unless materialized_key.is_a?(OpenSSL::PKey::RSA) && materialized_key.private?
            raise JWT::DecodeError, 'An RSA private key is required for decryption'
          end
          raise JWT::VerificationError, 'JWE decryption failed' unless encrypted_key.bytesize == materialized_key.n.num_bytes
        end
      end

      def validate_header!
        raise JWT::IncorrectAlgorithm, 'Unsupported JWE header parameter' if header.key?('crit')
        return unless header.key?('zip')

        raise JWT::IncorrectAlgorithm, 'Unsupported JWE header parameter'
      end

      def valid_direct_key?(key)
        key.is_a?(String) && key.bytesize == content_encryption_details[:key_length]
      end

      def unwrap_content_encryption_key(key)
        case header['alg']
        when 'dir'
          key_material(key).b
        when 'RSA-OAEP-256'
          RsaOaep256.decrypt(key_material(key), encrypted_key, expected_length: content_encryption_details[:key_length])
        end
      end

      def decrypt_content(key)
        cipher = OpenSSL::Cipher.new(content_encryption_details[:cipher])
        cipher.decrypt
        cipher.key = key
        cipher.iv = iv
        cipher.auth_tag = authentication_tag
        cipher.auth_data = encoded_header
        cipher.update(ciphertext)
        cipher.final

        verified_cipher = OpenSSL::Cipher.new(content_encryption_details[:cipher])
        verified_cipher.decrypt
        verified_cipher.key = key
        verified_cipher.iv = iv
        verified_cipher.auth_tag = authentication_tag
        verified_cipher.auth_data = encoded_header

        verified_cipher.update(ciphertext) + verified_cipher.final
      rescue OpenSSL::Cipher::CipherError
        raise JWT::VerificationError, 'JWE decryption failed'
      end

      def content_encryption_details
        CIPHERS.fetch(header['enc'])
      end

      def key_material(key)
        return key.keypair if key.is_a?(JWT::JWK::KeyBase)

        key
      end

      class << self
        private

        def content_encryption_key_for_encryption(alg, key, key_length)
          case alg
          when 'dir'
            materialized_key = key.is_a?(JWT::JWK::KeyBase) ? key.keypair : key
            raise JWT::EncodeError, 'A symmetric encryption key is required' unless materialized_key.is_a?(String) && materialized_key.bytesize == key_length

            [materialized_key.b, String.new]
          when 'RSA-OAEP-256'
            materialized_key = key.is_a?(JWT::JWK::KeyBase) ? key.keypair : key
            unless materialized_key.is_a?(OpenSSL::PKey::RSA)
              raise JWT::EncodeError, 'An RSA key is required for encryption'
            end

            cipher = OpenSSL::Cipher.new(key_length == 16 ? 'aes-128-gcm' : 'aes-256-gcm')
            content_encryption_key = cipher.random_key
            [content_encryption_key, RsaOaep256.encrypt(materialized_key, content_encryption_key)]
          end
        end

      def encrypt_content(cipher_name, key, iv, plaintext, encoded_header)
          cipher = OpenSSL::Cipher.new(cipher_name)
          cipher.encrypt
          cipher.key = key
          cipher.iv = iv
          cipher.auth_data = encoded_header
          ciphertext = cipher.update(plaintext) + cipher.final
          [ciphertext, cipher.auth_tag]
        end
      end
    end
  end
end
