# frozen_string_literal: true

require_relative '../jwa/eddsa'

module JWT
  module JWK
    # JWK representation for Octet Key Pair (OKP) keys as specified in
    # https://datatracker.ietf.org/doc/html/rfc8037
    #
    # Currently only the Ed25519 curve (used together with the EdDSA
    # algorithm) is supported, using the Ed25519 implementation provided by
    # the Ruby OpenSSL standard library.
    class OKP < KeyBase
      KTY = 'OKP'

      # JWK parameters holding the public part of the key (RFC 8037 section 2).
      OKP_PUBLIC_KEY_ELEMENTS  = %i[kty crv x].freeze
      OKP_PRIVATE_KEY_ELEMENTS = %i[d].freeze
      OKP_KEY_ELEMENTS = (OKP_PRIVATE_KEY_ELEMENTS + OKP_PUBLIC_KEY_ELEMENTS).freeze

      # Curve name mapped to the byte length of its octet string key parts.
      SUPPORTED_CURVES = {
        'Ed25519' => 32
      }.freeze

      # On OpenSSL gems older than 4 Ed25519 keys have a dedicated class while
      # newer versions represent the Edwards curves with the generic PKey.
      OPENSSL_KEY_CLASS = defined?(::OpenSSL::PKey::ED25519) ? ::OpenSSL::PKey::ED25519 : ::OpenSSL::PKey::PKey

      KTYS = [KTY, OPENSSL_KEY_CLASS, JWT::JWK::OKP].freeze

      def initialize(key, params = nil, options = {})
        params ||= {}

        # For backwards compatibility when kid was a String
        params = { kid: params } if params.is_a?(String)

        key_params = extract_key_params(key)

        params = params.transform_keys(&:to_sym)
        check_jwk_params!(key_params, params)

        # Build the OpenSSL key eagerly so that malformed key material (wrong
        # octet lengths or a mismatching key pair) is rejected at import time.
        @okp_key = create_okp_key(key_params[:x], key_params[:d])

        # A private key seed always determines its public counterpart, so the
        # JWK always carries the canonical public octet string.
        key_params[:x] = ::JWT::Base64.url_encode(@okp_key.raw_public_key)

        super(options, key_params.merge(params))
      end

      def keypair
        @okp_key
      end

      def private?
        !self[:d].nil?
      end

      def signing_key
        @okp_key
      end

      def verify_key
        @okp_key
      end

      # Returns an OpenSSL key containing only the public part.
      def public_key
        return @okp_key unless private?

        OpenSSL::PKey.new_raw_public_key(JWA::Eddsa::SUPPORTED_CURVE, @okp_key.raw_public_key)
      end

      def members
        OKP_PUBLIC_KEY_ELEMENTS.each_with_object({}) { |i, h| h[i] = self[i] }
      end

      def export(options = {})
        exported = parameters.clone
        exported.reject! { |k, _| OKP_PRIVATE_KEY_ELEMENTS.include?(k) } unless private? && options[:include_private] == true
        exported
      end

      def key_digest
        x_octets = decode_octets(self[:x])
        sequence = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::OctetString(x_octets),
                                            OpenSSL::ASN1::UTF8String.new(self[:crv]),
                                            OpenSSL::ASN1::UTF8String.new(KTY)])
        OpenSSL::Digest::SHA256.hexdigest(sequence.to_der)
      end

      def []=(key, value)
        raise ArgumentError, 'cannot overwrite cryptographic key attributes' if OKP_KEY_ELEMENTS.include?(key.to_sym)

        super
      end

      def jwa
        return super if self[:alg]

        JWA.resolve(JWA::Eddsa::ALG)
      end

      class << self
        def import(jwk_data)
          new(jwk_data)
        end
      end

      private

      def extract_key_params(key)
        case key
        when JWT::JWK::OKP
          key.export(include_private: true)
        when OPENSSL_KEY_CLASS
          parse_okp_key(key)
        when Hash
          key.transform_keys(&:to_sym)
        else
          raise ArgumentError, 'key must be an Ed25519 OpenSSL key or a Hash with key parameters'
        end
      end

      def parse_okp_key(key)
        unless JWA::Eddsa.ed25519_key?(key)
          curve_name = key.respond_to?(:oid) ? key.oid : key.class
          raise JWT::JWKError, "Unsupported curve '#{curve_name}'"
        end

        params = {
          kty: KTY,
          crv: JWA::Eddsa::SUPPORTED_CURVE,
          x: ::JWT::Base64.url_encode(key.raw_public_key)
        }

        d_octets = raw_private_octets(key)
        params[:d] = ::JWT::Base64.url_encode(d_octets) if d_octets
        params
      end

      def raw_private_octets(key)
        key.raw_private_key
      rescue OpenSSL::PKey::PKeyError
        nil
      end

      def check_jwk_params!(key_params, params)
        raise ArgumentError, 'cannot overwrite cryptographic key attributes' unless (OKP_KEY_ELEMENTS & params.keys).empty?
        raise JWT::JWKError, "Incorrect 'kty' value: #{key_params[:kty]}, expected #{KTY}" unless key_params[:kty] == KTY

        crv = key_params[:crv]
        raise JWT::JWKError, "Unsupported curve '#{crv}'" unless SUPPORTED_CURVES.key?(crv)

        unless key_params[:x] || key_params[:d]
          raise JWT::JWKError, 'Key format is invalid for OKP: at least one of the x or d parameters must be present'
        end

        validate_octets!(key_params[:x], 'x', SUPPORTED_CURVES[crv])
        validate_octets!(key_params[:d], 'd', SUPPORTED_CURVES[crv])
      end

      def validate_octets!(encoded, name, expected_length)
        return unless encoded

        bytes = decode_octets(encoded)
        return if bytes.bytesize == expected_length

        raise JWT::JWKError, "Invalid OKP key: the '#{name}' parameter must be #{expected_length} bytes, got #{bytes.bytesize}"
      end

      def create_okp_key(jwk_x, jwk_d)
        if jwk_d
          key = OpenSSL::PKey.new_raw_private_key(JWA::Eddsa::SUPPORTED_CURVE, decode_octets(jwk_d))
          if jwk_x && key.raw_public_key != decode_octets(jwk_x)
            raise JWT::JWKError, 'Invalid OKP key: the public key (x) does not match the private key (d)'
          end
          key
        else
          OpenSSL::PKey.new_raw_public_key(JWA::Eddsa::SUPPORTED_CURVE, decode_octets(jwk_x))
        end
      rescue OpenSSL::PKey::PKeyError => e
        raise JWT::JWKError, "Could not build the OpenSSL key from the OKP parameters: #{e.message}"
      end

      def decode_octets(base64_encoded_octets)
        ::JWT::Base64.url_decode(base64_encoded_octets)
      end
    end
  end
end
