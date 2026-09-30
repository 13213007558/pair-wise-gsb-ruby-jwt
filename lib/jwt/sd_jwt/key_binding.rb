# frozen_string_literal: true

module JWT
  module SDJWT
    # Builds and verifies the holder Key Binding JWT defined by RFC 9901.
    class KeyBinding
      HEADER_TYP = 'kb+jwt'

      Result = Struct.new(:jwt, :payload, :header)

      def self.create(presentation_input:, hash_algorithm:, holder_key:, audience:, nonce:, now:, algorithm: 'ES256', header_fields: {})
        payload = {
          'iat' => numeric_time(now),
          'aud' => audience,
          'nonce' => nonce,
          'sd_hash' => hash_algorithm.digest(presentation_input)
        }
        header = header_fields.transform_keys(&:to_s).merge('typ' => HEADER_TYP)
        jwt = JWT.encode(payload, holder_key, algorithm, header)
        Result.new(jwt, payload, header)
      end

      def self.verify(jwt:, cnf_jwk:, presentation_input:, hash_algorithm:, audience:, nonce:, now:, algorithm: 'ES256', leeway: 0)
        new(jwt, cnf_jwk, presentation_input, hash_algorithm).verify!(
          audience: audience,
          nonce: nonce,
          now: numeric_time(now),
          algorithm: algorithm,
          leeway: leeway
        )
      end

      def initialize(jwt, expected_jwk, presentation_input, hash_algorithm)
        @jwt = jwt
        @expected_jwk = expected_jwk
        @presentation_input = presentation_input
        @hash_algorithm = hash_algorithm
      end

      def verify!(audience:, nonce:, now:, algorithm:, leeway:)
        jwk = JWT::JWK.create_from(@expected_jwk)
        payload, header = JWT.decode(@jwt, verification_key(jwk), true, decode_options(algorithm))
        verify_header!(header)
        verify_payload!(payload, audience, nonce, now, leeway)
        Result.new(@jwt, payload, header)
      end

      private

      def self.numeric_time(time)
        time.is_a?(Numeric) ? time : time.to_f
      end

      def verify_header!(header)
        raise KeyBindingError, 'Key Binding JWT typ must be kb+jwt' unless header['typ'] == HEADER_TYP
      end

      def verify_payload!(payload, audience, nonce, now, leeway) # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
        raise KeyBindingError, 'Key Binding iat must be numeric' unless payload['iat'].is_a?(Numeric)
        iat = payload['iat'].to_f
        raise KeyBindingError, 'Key Binding iat is too far in the future' if iat > now + leeway
        raise KeyBindingError, 'Key Binding iat is too old' if iat < now - leeway

        actual_audience = Array(payload['aud']).map(&:to_s)
        expected_audience = Array(audience).map(&:to_s)
        raise KeyBindingError, 'Key Binding audience mismatch' if (actual_audience & expected_audience).empty?
        unless payload['nonce'].is_a?(::String) && nonce.is_a?(::String)
          raise KeyBindingError, 'Key Binding nonce must be a string'
        end
        raise KeyBindingError, 'Key Binding nonce mismatch' unless secure_compare(payload['nonce'].to_s, nonce.to_s)

        sd_hash = @hash_algorithm.digest(@presentation_input)
        raise KeyBindingError, 'Key Binding sd_hash mismatch' unless secure_compare(payload['sd_hash'].to_s, sd_hash)
      end

      def decode_options(algorithm)
        {
          algorithm: algorithm,
          verify_expiration: false,
          verify_not_before: false
        }
      end

      def verification_key(jwk)
        return jwk.verify_key if jwk.respond_to?(:verify_key)

        jwk
      end

      def secure_compare(left, right)
        JWT::JWA::Hmac::SecurityUtils.secure_compare(left, right)
      end

      def numeric_time(time)
        self.class.send(:numeric_time, time)
      end
    end
  end
end
