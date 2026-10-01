# frozen_string_literal: true

module JWT
  module JWK
    # JWK representation for Octet Key Pair (OKP) keys as defined in
    # RFC 8037. Only the Ed25519 curve is supported.
    class OKP < KeyBase
      KTY    = 'OKP'
      KTYS   = [KTY, JWT::JWK::OKP].freeze

      # The supported curves mapped to the names OpenSSL uses.
      CURVES = {
        'Ed25519' => 'ED25519'
      }.freeze

      # Ed25519 public keys and private seeds are both 32 octets (RFC 8037).
      KEY_OCTET_LENGTH = 32

      PUBLIC_KEY_ELEMENTS  = %i[kty crv x].freeze
      PRIVATE_KEY_ELEMENTS = %i[d].freeze
      KEY_ELEMENTS         = (PRIVATE_KEY_ELEMENTS + PUBLIC_KEY_ELEMENTS).freeze

      def initialize(key, params = nil, options = {})
        params ||= {}

        # For backwards compatibility when kid was a String
        params = { kid: params } if params.is_a?(String)

        key_params = extract_key_params(key)

        params = params.transform_keys(&:to_sym)
        check_jwk_params!(key_params, params)

        super(options, key_params.merge(params))

        # Build the key eagerly so that malformed coordinates, wrong lengths
        # and private/public mismatches are reported during import and not
        # only at first use.
        okp_key
      end

      def keypair
        okp_key
      end

      def private?
        !self[:d].nil?
      end

      def signing_key
        okp_key
      end

      def verify_key
        okp_key
      end

      # Returns the public part of the key as an OpenSSL key.
      def public_key
        OpenSSL::PKey.new_raw_public_key(self.class.openssl_curve(self[:crv]), decode_octets(self[:x], :x))
      end

      def members
        PUBLIC_KEY_ELEMENTS.each_with_object({}) { |i, h| h[i] = self[i] }
      end

      def export(options = {})
        exported = parameters.clone
        exported.reject! { |k, _| PRIVATE_KEY_ELEMENTS.include?(k) } unless private? && options[:include_private] == true
        exported
      end

      def key_digest
        # RFC 8037, Section 2 defines the canonical key representation as the
        # JSON object of the public key parameters. The digest uses the same
        # representation, only hex encoded like for the other key types.
        canonical = JWT::JSON.generate(members.sort.to_h)
        OpenSSL::Digest::SHA256.hexdigest(canonical)
      end

      def []=(key, value)
        raise ArgumentError, 'cannot overwrite cryptographic key attributes' if KEY_ELEMENTS.include?(key.to_sym)

        super
      end

      def jwa
        return super if self[:alg]

        JWA.resolve('EdDSA')
      end

      class << self
        def import(jwk_data)
          new(jwk_data)
        end

        # Returns the OpenSSL key type name for a JWK curve name.
        def openssl_curve(jwk_crv)
          CURVES.fetch(jwk_crv) do
            raise JWT::JWKError, "Unsupported curve '#{jwk_crv}'"
          end
        end
      end

      private

      def okp_key
        @okp_key ||= create_okp_key(self[:crv], self[:x], self[:d])
      end

      def extract_key_params(key)
        case key
        when JWT::JWK::OKP
          key.export(include_private: true)
        when OpenSSL::PKey::PKey # Accept an OpenSSL key as input
          parse_okp_key(key)
        when Hash
          key.transform_keys(&:to_sym)
        else
          raise ArgumentError, 'key must be of type OpenSSL::PKey::PKey or Hash with key parameters'
        end
      end

      def check_jwk_params!(key_params, params)
        raise ArgumentError, 'cannot overwrite cryptographic key attributes' unless (KEY_ELEMENTS & params.keys).empty?
        raise JWT::JWKError, "Incorrect 'kty' value: #{key_params[:kty]}, expected #{KTY}" unless key_params[:kty] == KTY

        crv = key_params[:crv]
        raise JWT::JWKError, "Unsupported curve '#{crv}'" unless CURVES.key?(crv)

        raise JWT::JWKError, 'Key format is invalid for OKP' unless key_params[:x]
      end

      def parse_okp_key(key)
        curve_name = CURVES.key(key.oid)
        raise JWT::JWKError, "Unsupported curve '#{key.oid}'" unless curve_name

        {
          kty: KTY,
          crv: curve_name,
          x: encode_octets(key.raw_public_key),
          d: encode_octets(extract_raw_private_key(key))
        }.compact
      end

      # Generic provider keys do not respond to #private?, so the presence of
      # the raw private key bytes is probed instead.
      def extract_raw_private_key(key)
        key.raw_private_key
      rescue OpenSSL::PKey::PKeyError
        nil
      end

      # Builds the OpenSSL key from the JWK coordinates. The key parts are
      # fixed length byte strings (RFC 8037, Section 2):
      # - x is the 32 octet public key
      # - d is the 32 octet private key seed
      def create_okp_key(jwk_crv, jwk_x, jwk_d)
        curve = self.class.openssl_curve(jwk_crv)
        x_octets = decode_octets(jwk_x, :x)
        validate_octet_length!(x_octets, :x, curve)

        if jwk_d
          d_octets = decode_octets(jwk_d, :d)
          validate_octet_length!(d_octets, :d, curve)

          OpenSSL::PKey.new_raw_private_key(curve, d_octets).tap do |key|
            # The public key encoded in x has to match the one derived from d.
            unless key.raw_public_key == x_octets
              raise JWT::JWKError, 'The private and public key parts do not match'
            end
          end
        else
          OpenSSL::PKey.new_raw_public_key(curve, x_octets)
        end
      rescue OpenSSL::PKey::PKeyError => e
        raise JWT::JWKError, "Key could not be created for curve '#{jwk_crv}': #{e.message}"
      end

      def validate_octet_length!(octets, part, curve)
        return if octets.bytesize == KEY_OCTET_LENGTH

        raise JWT::JWKError, "The '#{part}' parameter has to be #{KEY_OCTET_LENGTH} bytes for curve '#{curve}'"
      end

      def decode_octets(base64_encoded_octets, part)
        ::JWT::Base64.url_decode(base64_encoded_octets)
      rescue JWT::Base64DecodeError, NoMethodError, TypeError
        raise JWT::JWKError, "The '#{part}' parameter is not valid base64url encoded data"
      end

      def encode_octets(octets)
        return unless octets

        ::JWT::Base64.url_encode(octets)
      end
    end
  end
end
