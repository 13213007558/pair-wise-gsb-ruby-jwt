# frozen_string_literal: true

module JWT
  module SDJWT
    # Names of the hash algorithms as they appear in the "_sd_alg" claim and
    # the corresponding OpenSSL digest names.
    DIGEST_ALGORITHMS = {
      'sha-256' => 'SHA256',
      'sha-384' => 'SHA384',
      'sha-512' => 'SHA512',
      'sha3-256' => 'SHA3-256',
      'sha3-384' => 'SHA3-384',
      'sha3-512' => 'SHA3-512'
    }.freeze

    # The only hash algorithm an issuer is allowed to use per RFC 9901.
    DEFAULT_SD_ALG = 'sha-256'

    # Small helper used both for disclosure digests and the Key Binding JWT
    # "sd_hash" claim.
    class Digestable
      # @param algorithm [String] the "_sd_alg" algorithm name, defaults to sha-256.
      def initialize(algorithm = DEFAULT_SD_ALG)
        @algorithm = algorithm || DEFAULT_SD_ALG
        @openssl_name = DIGEST_ALGORITHMS[@algorithm] ||
                        raise(JWT::SDJWTFormatError, "Unsupported _sd_alg algorithm: #{@algorithm}")
      end

      # @param data [String] the data to hash.
      # @return [String] the hex encoded digest.
      def digest(data)
        ::OpenSSL::Digest.new(@openssl_name).digest(data).unpack1('H*')
      end
    end
  end
end
