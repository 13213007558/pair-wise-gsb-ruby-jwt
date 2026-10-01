# frozen_string_literal: true

require_relative 'jwk/key_finder'
require_relative 'jwk/set'

module JWT
  # JSON Web Key (JWK)
  module JWK
    class << self
      def create_from(key, params = nil, options = {})
        if key.is_a?(Hash)
          jwk_kty = key[:kty] || key['kty']
          raise JWT::JWKError, 'Key type (kty) not provided' unless jwk_kty

          return mappings.fetch(jwk_kty.to_s) do |kty|
            raise JWT::UnsupportedKeyType, "Key type #{kty} not supported"
          end.new(key, params, options)
        end

        jwk_class_from(key).new(key, params, options)
      end

      # Ed25519 keys are represented by the generic OpenSSL::PKey::PKey class
      # and need to be distinguished by their OID instead of their class.
      def jwk_class_from(key)
        mappings[key.class] ||
          (JWT::JWA::Eddsa.ed25519_key?(key) ? OKP : nil) ||
          raise(JWT::JWKError, "Cannot create JWK from a #{key.class.name}")
      end

      def classes
        @mappings = nil # reset the cached mappings
        @classes ||= []
      end

      alias new create_from
      alias import create_from

      private

      def mappings
        @mappings ||= generate_mappings
      end

      def generate_mappings
        classes.each_with_object({}) do |klass, hash|
          next unless klass.const_defined?('KTYS')

          Array(klass::KTYS).each do |kty|
            hash[kty] = klass
          end
        end
      end
    end
  end
end

require_relative 'jwk/key_base'
require_relative 'jwk/ec'
require_relative 'jwk/okp'
require_relative 'jwk/rsa'
require_relative 'jwk/hmac'
