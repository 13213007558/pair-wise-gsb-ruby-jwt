# frozen_string_literal: true

require 'openssl'

module JWT
  module SDJWT
    # Digest and hash helpers used by the SD-JWT (RFC 9901) processing.
    #
    # All hashing is performed over UTF-8 encoded JSON / binary data, and the
    # digests are returned base64url encoded without padding, exactly as the
    # specification requires.
    module Hasher
      # The hash algorithms allowed by RFC 9901 for the `_sd_alg` claim.
      SUPPORTED_ALGORITHMS = %w[sha-256 sha-384 sha-512].freeze

      class << self
        # Returns the base64url encoded digest of the given data.
        #
        # @param data [String] the binary data to hash.
        # @param algorithm [String] one of `sha-256`, `sha-384` or `sha-512`.
        # @return [String] the base64url encoded digest.
        # @raise [JWT::SDJWTError] if the algorithm is not supported.
        def digest(data, algorithm = 'sha-256')
          ::JWT::Base64.url_encode(hash_binary(data, algorithm))
        end

        # Returns the raw binary digest of the given data.
        #
        # @param data [String] the binary data to hash.
        # @param algorithm [String] one of `sha-256`, `sha-384` or `sha-512`.
        # @return [String] the raw digest bytes.
        # @raise [JWT::SDJWTError] if the algorithm is not supported.
        def hash_binary(data, algorithm = 'sha-256')
          raise ::JWT::SDJWTError, "Unsupported SD-JWT hash algorithm '#{algorithm}'" unless SUPPORTED_ALGORITHMS.include?(algorithm)

          ::OpenSSL::Digest.digest(algorithm, data)
        end

        # Generates a cryptographically random salt with at least 128 bits of
        # entropy as recommended by RFC 9901.
        #
        # @param bytes [Integer] number of random bytes.
        # @return [String] the base64url encoded salt.
        def random_salt(bytes = 16)
          ::JWT::Base64.url_encode(::OpenSSL::Random.random_bytes(bytes))
        end
      end
    end
  end
end
