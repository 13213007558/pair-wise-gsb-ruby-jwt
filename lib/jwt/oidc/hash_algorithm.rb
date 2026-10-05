# frozen_string_literal: true

require 'openssl'

module JWT
  module OIDC
    # Derives the digest used for the c_hash and at_hash claims from the
    # verified signature algorithm of the ID Token, as defined by
    # OpenID Connect Core 1.0 section 3.1.3.6.
    module HashAlgorithm
      # Explicit mapping between the supported JWS algorithms and the hash
      # algorithm of their JWA "alg" value. Algorithms not present in this
      # table (including "none") have no defined hash and are rejected
      # instead of silently falling back to SHA-256.
      ALGORITHM_DIGESTS = {
        'HS256' => 'SHA256',
        'RS256' => 'SHA256',
        'PS256' => 'SHA256',
        'ES256' => 'SHA256',
        'ES256K' => 'SHA256',
        'HS384' => 'SHA384',
        'RS384' => 'SHA384',
        'PS384' => 'SHA384',
        'ES384' => 'SHA384',
        'HS512' => 'SHA512',
        'RS512' => 'SHA512',
        'PS512' => 'SHA512',
        'ES512' => 'SHA512'
      }.freeze

      class << self
        # Returns the digest for the given JWS algorithm.
        #
        # @param algorithm [String] the verified JWS "alg" header value.
        # @return [OpenSSL::Digest] the digest instance.
        # @raise [JWT::OIDC::UnsupportedAlgorithmError] if the algorithm has no defined hash algorithm.
        def digest_for(algorithm)
          digest_name = ALGORITHM_DIGESTS[algorithm.to_s.upcase]
          raise UnsupportedAlgorithmError, "Cannot derive a hash algorithm from the signing algorithm #{algorithm.inspect}" unless digest_name

          OpenSSL::Digest.new(digest_name)
        end

        # Computes the value of a c_hash or at_hash claim: the base64url
        # encoded left-most half of the hash of the ASCII representation of
        # the authorization code or access token.
        #
        # @param algorithm [String] the verified JWS "alg" header value.
        # @param value [String] the authorization code or access token.
        # @return [String] the expected claim value.
        def hash_token(algorithm, value)
          digest = digest_for(algorithm)
          ::JWT::Base64.url_encode(digest.digest(value.to_s)[0, digest.digest_length / 2])
        end
      end
    end
  end
end
