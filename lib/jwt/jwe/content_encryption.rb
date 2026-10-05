# frozen_string_literal: true

module JWT
  module JWE
    # Content encryption algorithms for JWE (RFC 7518 section 5).
    module ContentEncryption
      # AES in Galois/Counter Mode (RFC 7518 5.3).
      #
      # The authentication tag is verified before any plaintext is returned;
      # authentication failures raise {JWT::DecryptionError} without exposing
      # key material or decrypted content.
      class Gcm
        IV_LENGTH = 12
        TAG_LENGTH = 16

        attr_reader :alg, :cek_length

        def initialize(alg, cek_length)
          @alg = alg
          @cek_length = cek_length
        end

        # Encrypts the plaintext. Returns [iv, ciphertext, tag].
        def encrypt(cek:, plaintext:, aad:)
          cipher = new_cipher
          cipher.encrypt
          cipher.key = cek
          iv = cipher.random_iv
          cipher.auth_data = aad
          ciphertext = cipher.update(plaintext) + cipher.final
          [iv, ciphertext, cipher.auth_tag]
        end

        # Decrypts the ciphertext, verifying the authentication tag first.
        def decrypt(cek:, iv:, ciphertext:, tag:, aad:)
          validate_lengths!(cek, iv, tag)
          cipher = new_cipher
          cipher.decrypt
          cipher.key = cek
          cipher.iv = iv
          cipher.auth_tag = tag
          cipher.auth_data = aad
          cipher.update(ciphertext) + cipher.final
        rescue ::OpenSSL::Cipher::CipherError
          raise ::JWT::DecryptionError, 'JWE decryption failed'
        end

        private

        def validate_lengths!(cek, iv, tag)
          valid = cek.is_a?(String) && cek.bytesize == cek_length &&
                  iv.is_a?(String) && iv.bytesize == IV_LENGTH &&
                  tag.is_a?(String) && tag.bytesize == TAG_LENGTH
          raise ::JWT::DecryptionError, 'JWE decryption failed' unless valid
        end

        def new_cipher
          ::OpenSSL::Cipher.new("aes-#{cek_length * 8}-gcm")
        end
      end

      @algorithms = {}

      class << self
        def register(algorithm)
          @algorithms[algorithm.alg] = algorithm
        end

        # Returns the registered algorithm matching +name+, or nil.
        def find(name)
          @algorithms[name]
        end
      end

      register(Gcm.new('A128GCM', 16))
      register(Gcm.new('A256GCM', 32))
    end
  end
end
