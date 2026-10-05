# frozen_string_literal: true

module JWT
  module JWE
    # Key management algorithms for JWE (RFC 7518 section 4).
    #
    # Each algorithm knows how to wrap (encrypt) and unwrap (decrypt) the
    # Content Encryption Key (CEK) for a given content encryption algorithm.
    module KeyManagement
      # Base functionality shared by key management algorithms.
      class Base
        attr_reader :alg

        def initialize(alg)
          @alg = alg
        end

        # Wraps a freshly generated CEK. Returns [cek, encrypted_key].
        def wrap(_key, _cek_length)
          raise ::JWT::JWEError, "Key management algorithm #{alg} does not support key wrapping"
        end

        # Unwraps the CEK from the encrypted key segment.
        def unwrap(_encrypted_key, _key, _cek_length)
          raise ::JWT::JWEError, "Key management algorithm #{alg} does not support key unwrapping"
        end

        private

        def validate_cek_length!(cek, cek_length)
          return if cek.is_a?(String) && cek.bytesize == cek_length

          raise ::JWT::JWEError, "The given key does not match the #{cek_length * 8}-bit CEK required by the content encryption algorithm"
        end
      end

      # Direct use of a shared symmetric key as the CEK ("dir", RFC 7518 4.5).
      class Dir < Base
        def wrap(key, cek_length)
          validate_cek_length!(key, cek_length)

          [key, '']
        end

        def unwrap(encrypted_key, key, cek_length)
          raise ::JWT::DecryptionError, 'JWE decryption failed' unless encrypted_key.empty?

          validate_cek_length!(key, cek_length)

          key
        end
      end

      # RSAES OAEP using SHA-256 and MGF1 with SHA-256 ("RSA-OAEP-256", RFC 7518 4.3).
      class RsaOaep256 < Base
        OAEP_OPTIONS = {
          'rsa_padding_mode' => 'oaep',
          'rsa_oaep_md' => 'sha256',
          'rsa_mgf1_md' => 'sha256'
        }.freeze

        def wrap(key, cek_length)
          validate_rsa_key!(key)

          cek = ::OpenSSL::Random.random_bytes(cek_length)
          [cek, key.encrypt(cek, OAEP_OPTIONS)]
        rescue ::OpenSSL::PKey::PKeyError
          raise ::JWT::JWEError, 'Unable to wrap the content encryption key'
        end

        def unwrap(encrypted_key, key, cek_length)
          validate_rsa_key!(key)

          cek = key.decrypt(encrypted_key, OAEP_OPTIONS)
          raise ::JWT::DecryptionError, 'JWE decryption failed' unless cek.bytesize == cek_length

          cek
        rescue ::OpenSSL::PKey::PKeyError
          raise ::JWT::DecryptionError, 'JWE decryption failed'
        end

        private

        def validate_rsa_key!(key)
          return if key.is_a?(::OpenSSL::PKey::RSA)

          raise ::JWT::JWEError, "The given key is a #{key.class}. It has to be an OpenSSL::PKey::RSA instance"
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

      register(Dir.new('dir'))
      register(RsaOaep256.new('RSA-OAEP-256'))
    end
  end
end
