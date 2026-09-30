# frozen_string_literal: true

require_relative '../jwa'
require_relative 'signature'

module JWT
  module JWS
    # Signs a payload for a JWS JSON Serialization.
    #
    # A signer always places the algorithm and any other sensitive header
    # parameters in the protected header. Unprotected parameters may be added
    # through the :header option but must not share names with the protected
    # parameters.
    #
    # @example
    #   signer = JWT::JWS::Signer.new(algorithm: 'HS256', key: 'secret', header: { 'kid' => 'one' })
    #   signature = signer.sign(encoded_payload)
    class Signer
      # @return [Object] the key used for signing.
      attr_reader :key

      # @return [String, Object] the algorithm used for signing.
      attr_reader :algorithm

      # @return [Hash] the unprotected header parameters.
      attr_reader :header

      # @return [Hash] the protected header parameters as given by the caller.
      attr_reader :protected_header

      # @param key [String, OpenSSL::PKey::PKey, JWT::JWK::KeyBase] the signing key.
      # @param algorithm [String, Object] the signing algorithm.
      # @param protected_header [Hash] header parameters protected by the signature.
      # @param header [Hash] unprotected header parameters.
      def initialize(key:, algorithm:, protected_header: {}, header: {})
        @key       = key
        @algorithm = algorithm
        @protected_header = normalize(protected_header, 'Protected header')
        @header           = normalize(header, 'Unprotected header')

        validate_headers!
      end

      # Signs the encoded payload.
      #
      # @param encoded_payload [String] the Base64url encoded payload shared by all signatures.
      # @return [JWT::JWS::Signature] the produced signature.
      def sign(encoded_payload)
        jwa = JWA.create_signer(algorithm: algorithm, key: key)

        header = build_protected_header!(jwa)
        encoded_header = ::JWT::Base64.url_encode(JWT::JSON.generate(header))

        signature_bytes = jwa.sign(data: [encoded_header, encoded_payload].join('.'))

        Signature.new(
          protected_header: encoded_header,
          header: self.header.empty? ? nil : self.header,
          signature: ::JWT::Base64.url_encode(signature_bytes)
        )
      end

      private

      def normalize(value, name)
        raise ::JWT::EncodeError, "#{name} must be a Hash" unless value.nil? || value.is_a?(::Hash)

        (value || {}).transform_keys(&:to_s)
      end

      def validate_headers!
        overlapping = protected_header.keys & header.keys
        raise ::JWT::EncodeError, "Header parameter '#{overlapping.first}' must not be present in both protected and unprotected headers" unless overlapping.empty?

        given_alg = protected_header['alg']
        return if given_alg.nil?

        return if JWA.resolve(algorithm).valid_alg?(given_alg)

        raise ::JWT::IncorrectAlgorithm, 'Algorithm option and protected header alg do not match'
      end

      def build_protected_header!(signer)
        header = signer.jwa.header.merge(protected_header) { |_name, _generated, given| given }
        raise ::JWT::EncodeError, "Protected header alg '#{header['alg']}' does not match the signing algorithm" unless JWA.resolve(algorithm).valid_alg?(header['alg'])

        header
      end
    end
  end
end
