# frozen_string_literal: true

require 'set'

require_relative 'sd_jwt/error'
require_relative 'sd_jwt/hash_algorithm'
require_relative 'sd_jwt/disclosure'
require_relative 'sd_jwt/compact'
require_relative 'sd_jwt/issuer'
require_relative 'sd_jwt/selector'
require_relative 'sd_jwt/key_binding'
require_relative 'sd_jwt/verifier'

module JWT
  # Selective Disclosure JWT (RFC 9901) helpers.
  module SDJWT
    module_function

    def issue(payload:, signer_key:, algorithm: 'ES256', header_fields: {}, # rubocop:disable Metrics/ParameterLists
             disclosable_paths: [], decoys: 0, holder_jwk: nil,
             sd_alg: 'sha-256', rng: SecureRandom, salt_bytes: 16)
      Issuer.new(
        payload: payload,
        signer_key: signer_key,
        algorithm: algorithm,
        header_fields: header_fields,
        disclosable_paths: disclosable_paths,
        decoys: decoys,
        holder_jwk: holder_jwk,
        sd_alg: sd_alg,
        rng: rng,
        salt_bytes: salt_bytes
      ).issue
    end

    def disclose(issued_token, paths = :all)
      Selector.new(issued_token).disclose(paths)
    end

    def present(issued_token, paths: :all, key_binding: nil)
      Selector.new(issued_token).present(paths: paths, key_binding: key_binding)
    end

    def verify(token, issuer_key, algorithm:, key_binding: nil)
      Verifier.new(token, issuer_key, algorithm: algorithm).verify!(key_binding: key_binding)
    end
  end
end
