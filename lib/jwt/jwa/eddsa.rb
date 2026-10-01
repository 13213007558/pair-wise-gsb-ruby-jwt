# frozen_string_literal: true

module JWT
  module JWA
    # Edwards-curve Digital Signature Algorithm (EdDSA), RFC 8032.
    #
    # Currently only the Ed25519 curve as used by the "EdDSA" JWS algorithm
    # (RFC 8037) is supported. Signing and verification is performed through
    # the OpenSSL library, no additional gems are required.
    class Eddsa
      include JWT::JWA::SigningAlgorithm

      # OpenSSL uses this name for the Ed25519 key type.
      KEY_TYPE = 'ED25519'

      def initialize(alg = 'EdDSA')
        @alg = alg
      end

      def sign(data:, signing_key:)
        unless ed25519_key?(signing_key)
          raise_sign_error!("The given key is a #{signing_key.class}. It has to be an OpenSSL Ed25519 (PKey) instance")
        end
        raise_sign_error!('The given key is not a private key') unless private_key?(signing_key)

        # Ed25519 performs PureEdDSA: the message itself is signed, no digest
        # is applied beforehand. OpenSSL therefore expects a +nil+ digest.
        signing_key.sign(nil, data)
      rescue ::OpenSSL::PKey::PKeyError => e
        raise_sign_error!(e.message)
      end

      def verify(data:, signature:, verification_key:)
        unless ed25519_key?(verification_key)
          raise_verify_error!("The given key is a #{verification_key.class}. It has to be an OpenSSL Ed25519 (PKey) instance")
        end

        # OpenSSL returns false when the signature has the wrong size or does
        # not match the signing input.
        verification_key.verify(nil, signature, data)
      rescue ::OpenSSL::PKey::PKeyError, TypeError
        raise JWT::VerificationError, 'Signature verification raised'
      end

      register_algorithm(new)

      class << self
        # Checks that the given OpenSSL key is an Ed25519 key. Ed25519 keys are
        # represented by the generic OpenSSL::PKey::PKey class and can be
        # distinguished by their OID.
        def ed25519_key?(key)
          key.is_a?(::OpenSSL::PKey::PKey) && key.oid == KEY_TYPE
        rescue ::OpenSSL::PKey::PKeyError
          false
        end

        # Generic provider keys such as Ed25519 do not respond to #private?,
        # so the presence of the raw private key bytes is used instead.
        def private_key?(key)
          return key.private? if key.respond_to?(:private?)

          key.raw_private_key
          true
        rescue ::OpenSSL::PKey::PKeyError
          false
        end
      end

      private

      def ed25519_key?(key)
        self.class.ed25519_key?(key)
      end

      def private_key?(key)
        self.class.private_key?(key)
      end
    end
  end
end
