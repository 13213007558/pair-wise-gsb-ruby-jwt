# frozen_string_literal: true

require 'time'

require_relative 'constants'
require_relative 'hasher'
require_relative 'presentation'

module JWT
  module SDJWT
    # Builds and verifies the optional Key Binding JWT of an SD-JWT
    # (RFC 9901 section 4.3).
    #
    # The Key Binding JWT proves to a verifier that the holder of the
    # presentation controls the key referenced by the `cnf` claim of the
    # issuer JWT.
    module KeyBinding
      class << self
        # Computes the `sd_hash` for a presentation.
        #
        # @param jwt [String] the issuer JWT.
        # @param disclosures [Array<Disclosure, String>] the presented disclosures.
        # @param hash_algorithm [String] the hash algorithm of the SD-JWT.
        # @return [String] the base64url encoded digest.
        def sd_hash(jwt, disclosures, hash_algorithm = DEFAULT_HASH_ALGORITHM)
          encoded = disclosures.map { |entry| entry.is_a?(Disclosure) ? entry.encoded : entry }
          input = [jwt, *encoded, ''].join(SEPARATOR)
          Hasher.digest(input, hash_algorithm)
        end

        # Builds and signs a Key Binding JWT.
        #
        # @param presentation [Presentation] the presentation to bind to.
        # @param key [String, OpenSSL::PKey::PKey, JWT::JWK::KeyBase] the holder key.
        # @param audience [String, Array<String>] the intended audience.
        # @param nonce [String] the nonce provided by the verifier.
        # @param algorithm [String] the JWS algorithm, e.g. `ES256`.
        # @param iat [Integer] the issued-at time. Defaults to the current time.
        # @param exp [Integer, nil] optional expiration time of the KB-JWT.
        # @param header_fields [Hash] additional JWS header fields.
        # @return [String] the signed Key Binding JWT.
        def sign(presentation:, key:, audience:, nonce:, algorithm:, hash_algorithm: DEFAULT_HASH_ALGORITHM, iat: ::Time.now.to_i, exp: nil, header_fields: {})
          payload = {
            'iat' => iat,
            'aud' => audience,
            'nonce' => nonce,
            'sd_hash' => sd_hash(presentation.jwt, presentation.disclosures, hash_algorithm)
          }
          payload['exp'] = exp if exp
          headers = { 'typ' => KEY_BINDING_TYPE }.merge(stringify(header_fields))

          token = ::JWT::Token.new(payload: payload, header: headers)
          token.sign!(algorithm: algorithm, key: key)
          token.jwt
        end

        # Verifies a Key Binding JWT against a parsed presentation.
        #
        # @param presentation [Presentation] the presentation carrying the KB-JWT.
        # @param issuer_payload [Hash] the already verified payload of the issuer JWT.
        # @param audience [String, Array<String>] the expected audience.
        # @param nonce [String] the expected nonce.
        # @param hash_algorithm [String] the hash algorithm of the SD-JWT.
        # @param algorithms [Array<String>] acceptable KB JWS algorithms.
        # @param iat_leeway [Integer] seconds of tolerance for the `iat` claim.
        # @return [Hash] the verified Key Binding JWT claims.
        # @raise [JWT::SDJWTKeyBindingError] if the Key Binding JWT cannot be verified.
        def verify!(presentation:, issuer_payload:, audience:, nonce:, hash_algorithm: DEFAULT_HASH_ALGORITHM, algorithms: DEFAULT_ALGORITHMS, iat_leeway: 0)
          raise ::JWT::SDJWTKeyBindingError, 'Key Binding JWT is missing' unless presentation.key_binding_jwt

          encoded_token = parse_kb_jwt(presentation.key_binding_jwt)
          verify_kb_header!(encoded_token)
          signature_valid = encoded_token.valid_signature?(
            algorithm: algorithms, key: confirmation_jwk(issuer_payload)
          )
          unless signature_valid
            raise ::JWT::SDJWTKeyBindingError, 'Key Binding JWT signature verification failed'
          end

          claims = kb_claims(encoded_token)
          verify_iat!(claims, iat_leeway)
          verify_exp!(claims, iat_leeway)
          verify_audience!(claims, audience)
          verify_nonce!(claims, nonce)
          verify_sd_hash!(claims, presentation, hash_algorithm)

          claims
        end

        private

        DEFAULT_ALGORITHMS = %w[ES256 ES384 ES512 RS256 RS384 RS512 PS256 PS384 PS512 EdDSA].freeze
        private_constant(:DEFAULT_ALGORITHMS)

        def parse_kb_jwt(encoded_jwt)
          ::JWT::EncodedToken.new(encoded_jwt)
        rescue ::ArgumentError => e
          raise ::JWT::SDJWTKeyBindingError, e.message
        end

        def verify_kb_header!(encoded_token)
          unless encoded_token.header.is_a?(::Hash) && encoded_token.header['typ'] == KEY_BINDING_TYPE
            raise ::JWT::SDJWTKeyBindingError, "Key Binding JWT header typ must be '#{KEY_BINDING_TYPE}'"
          end
          if encoded_token.header['alg'].to_s == 'none'
            raise ::JWT::SDJWTKeyBindingError, "Key Binding JWT algorithm must not be 'none'"
          end
        end

        def kb_claims(encoded_token)
          claims = encoded_token.unverified_payload
          unless claims.is_a?(::Hash)
            raise ::JWT::SDJWTKeyBindingError, 'Key Binding JWT payload must be a JSON object'
          end

          claims
        end

        def confirmation_jwk(issuer_payload)
          jwk_data = issuer_payload.is_a?(::Hash) ? issuer_payload.dig('cnf', 'jwk') : nil
          unless jwk_data.is_a?(::Hash)
            raise ::JWT::SDJWTKeyBindingError, "Issuer JWT must contain a 'cnf.jwk' claim for Key Binding"
          end

          ::JWT::JWK.create_from(jwk_data)
        rescue ::JWT::JWKError => e
          raise ::JWT::SDJWTKeyBindingError, "Invalid 'cnf.jwk': #{e.message}"
        end

        def verify_iat!(claims, leeway)
          iat = claims['iat']
          unless iat.is_a?(::Numeric)
            raise ::JWT::SDJWTKeyBindingError, "Key Binding JWT 'iat' claim is required and must be a number"
          end
          return if leeway.zero?

          now = ::Time.now.to_i
          if iat > now + leeway || iat < now - leeway
            raise ::JWT::SDJWTKeyBindingError, "Key Binding JWT 'iat' is outside the allowed leeway"
          end
        end

        def verify_exp!(claims, leeway)
          exp = claims['exp']
          return if exp.nil?
          unless exp.is_a?(::Numeric)
            raise ::JWT::SDJWTKeyBindingError, "Key Binding JWT 'exp' claim must be a number"
          end
          return if exp >= ::Time.now.to_i - leeway

          raise ::JWT::SDJWTKeyBindingError, 'Key Binding JWT has expired'
        end

        def verify_audience!(claims, expected)
          actual = claims['aud']
          expected = Array(expected)
          actual = Array(actual)
          return unless actual.empty? || (expected & actual.map(&:to_s)).empty?

          raise ::JWT::SDJWTKeyBindingError, "Key Binding JWT 'aud' does not match the expected audience"
        end

        def verify_nonce!(claims, expected)
          return if expected && claims['nonce'] == expected

          raise ::JWT::SDJWTKeyBindingError, "Key Binding JWT 'nonce' does not match the expected nonce"
        end

        def verify_sd_hash!(claims, presentation, hash_algorithm)
          expected = sd_hash(presentation.jwt, presentation.disclosures, hash_algorithm)
          return if claims['sd_hash'].is_a?(::String) && secure_compare(claims['sd_hash'], expected)

          raise ::JWT::SDJWTKeyBindingError, "Key Binding JWT 'sd_hash' does not match the presentation"
        end

        def secure_compare(a, b)
          return false unless a.bytesize == b.bytesize

          l = a.unpack("C#{a.bytesize}")
          r = 0
          b.each_byte { |byte| r |= byte ^ l.shift }
          r.zero?
        end

        def stringify(hash)
          hash.each_with_object({}) { |(key, value), result| result[key.to_s] = value }
        end
      end
    end
  end
end
