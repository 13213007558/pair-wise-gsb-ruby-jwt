# frozen_string_literal: true

require 'digest'
require 'securerandom'

module JWT
  module SDJwt
    HASH_ALGORITHM = 'sha-256'
    SD_CLAIM = '_sd'
    SD_ALGORITHM_CLAIM = '_sd_alg'
    ARRAY_SD_MARKER = '...'
    KEY_BINDING_TYPE = 'kb+jwt'
    DIGEST_LENGTH = 32
  end
end

require_relative 'sd_jwt/disclosable'
require_relative 'sd_jwt/disclosure'
require_relative 'sd_jwt/errors'
require_relative 'sd_jwt/compact'
require_relative 'sd_jwt/issuer'
require_relative 'sd_jwt/presenter'
require_relative 'sd_jwt/result'
require_relative 'sd_jwt/verifier'

module JWT
  # Selective Disclosure for JWTs (RFC 9901)
  module SDJwt
    class << self
      def issue(payload:, signer:, disclosable_paths: [], decoy_digests: 0, holder_public_key: nil, headers: {})
        Issuer.new(
          payload: payload,
          signer: signer,
          disclosable_paths: disclosable_paths,
          decoy_digests: decoy_digests,
          holder_public_key: holder_public_key,
          headers: headers
        ).issue
      end

      def disclose(sd_jwt, claims: nil, paths: nil, key_binding: nil)
        Presenter.new(sd_jwt, claims: claims, paths: paths, key_binding: key_binding).present
      end

      def verify(sd_jwt, issuer_key:, algorithm:, current_time:, audience: nil, nonce: nil, holder_key: nil,
                 key_binding_algorithm: 'ES256', key_binding_leeway: 0, claims: nil)
        Verifier.new(
          sd_jwt: sd_jwt,
          issuer_key: issuer_key,
          algorithm: algorithm,
          current_time: current_time,
          audience: audience,
          nonce: nonce,
          holder_key: holder_key,
          key_binding_algorithm: key_binding_algorithm,
          key_binding_leeway: key_binding_leeway,
          claims: claims
        ).verify
      end

      def digest(encoded_disclosure)
        Base64.url_encode(OpenSSL::Digest::SHA256.digest(encoded_disclosure))
      end

      def key_thumbprint(public_key)
        JWT::JWK::Thumbprint.new(JWT::JWK.create_from(public_key)).generate
      end

      def sd_hash(sd_jwt_without_key_binding)
        digest(sd_jwt_without_key_binding)
      end
    end
  end
end
