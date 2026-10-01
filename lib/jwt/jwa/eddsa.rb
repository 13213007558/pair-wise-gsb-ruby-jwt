# frozen_string_literal: true

module JWT
  module JWA
    # Edwards-curve Digital Signature Algorithm (EdDSA) as described in
    # https://datatracker.ietf.org/doc/html/rfc8032 and registered for JWA in
    # https://datatracker.ietf.org/doc/html/rfc8037.
    #
    # The implementation uses the Ed25519 capabilities built into OpenSSL
    # (version 1.1.1 or later) through the Ruby OpenSSL standard library and
    # does not need any third party EdDSA gem.
    class Eddsa
      include JWT::JWA::SigningAlgorithm

      # Algorithm name used in JWS headers.
      ALG = 'EdDSA'

      # The only JWK curve supported by this implementation.
      SUPPORTED_CURVE = 'Ed25519'

      def initialize(alg = ALG)
        @alg = alg
      end

      register_algorithm(new)

      # Whether the OpenSSL version in use exposes native Ed25519 support.
      #
      # @return [Boolean]
      def self.supported?
        return @supported unless @supported.nil?

        @supported = OpenSSL::PKey.respond_to?(:new_raw_private_key) && ed25519_available?
      end

      # Whether an OpenSSL key object is an Ed25519 key.
      #
      # @param key [Object]
      # @return [Boolean]
      def self.ed25519_key?(key)
        return false unless key.is_a?(::OpenSSL::PKey::PKey)

        # OpenSSL gems 2.x/3.x provide a dedicated Ed25519 key class.
        return key.is_a?(::OpenSSL::PKey::ED25519) if defined?(::OpenSSL::PKey::ED25519)

        # OpenSSL gem 4.x represents the Edwards curves with the generic PKey
        # class and exposes the algorithm name through #oid. The reported name
        # is upper case ("ED25519").
        key.respond_to?(:oid) && key.oid.casecmp(SUPPORTED_CURVE).zero?
      end

      # Whether the given key contains a private part and can be used for signing.
      #
      # @param key [OpenSSL::PKey::PKey]
      # @return [Boolean]
      def self.private_key?(key)
        return false unless ed25519_key?(key)

        if key.respond_to?(:private?)
          key.private?
        else
          # OpenSSL gem 4.x removed PKey#private?; extracting the raw private
          # key only succeeds when the key actually contains one.
          !!key.raw_private_key
        end
      rescue OpenSSL::PKey::PKeyError
        false
      end

      def sign(data:, signing_key:)
        unless self.class.ed25519_key?(signing_key)
          raise_sign_error!("The given key is a #{signing_key.class}. It has to be an Ed25519 (OKP) key")
        end
        raise_sign_error!('The given key is not a private key') unless self.class.private_key?(signing_key)

        signing_key.sign(nil, data)
      end

      def verify(data:, signature:, verification_key:)
        unless self.class.ed25519_key?(verification_key)
          raise_verify_error!("The given key is a #{verification_key.class}. It has to be an Ed25519 (OKP) key")
        end

        verification_key.verify(nil, signature, data)
      rescue OpenSSL::PKey::PKeyError, TypeError
        raise JWT::VerificationError, 'Signature verification raised'
      end

      class << self
        private

        # A generation round trip is the most portable probe across the
        # supported OpenSSL gem versions.
        def ed25519_available?
          ed25519_key?(::OpenSSL::PKey.generate_key(SUPPORTED_CURVE))
        rescue StandardError
          false
        end
      end
    end
  end
end
