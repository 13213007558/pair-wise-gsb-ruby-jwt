# frozen_string_literal: true

require 'digest'

module JWT
  module JWS
    # Builds a stable identity for verification keys.
    #
    # Signatures made with the same key, even if the key object appears twice in
    # the verification input, share one identity and can therefore not be
    # counted as signatures from two independent signers.
    module KeyIdentity
      class << self
        # @param key [String, OpenSSL::PKey::PKey, JWT::JWK::KeyBase] a verification key.
        # @return [String] a stable identity for the key.
        def of(key)
          case key
          when ::JWT::JWK::KeyBase
            "jwk:#{key.kid}"
          when ::String
            "hmac:#{::Digest::SHA256.digest(key)}"
          when ::OpenSSL::PKey::PKey
            "pkey:#{key.public_key.to_der}"
          when ::JWT::JWS::Signature
            'alg:none'
          else
            "other:#{key.class}:#{key.hash}"
          end
        end
      end
    end
  end
end
