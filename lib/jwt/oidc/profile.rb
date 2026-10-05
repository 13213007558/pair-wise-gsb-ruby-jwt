# frozen_string_literal: true

module JWT
  module OIDC
    # Verifies the OpenID Connect claims that bind an ID token to an
    # authorization response and the requesting client.
    class Profile
      FLOWS = %i[code implicit hybrid].freeze

      HASH_ALGORITHMS = {
        'HS256' => 'sha256',
        'HS384' => 'sha384',
        'HS512' => 'sha512',
        'RS256' => 'sha256',
        'RS384' => 'sha384',
        'RS512' => 'sha512',
        'PS256' => 'sha256',
        'PS384' => 'sha384',
        'PS512' => 'sha512',
        'ES256' => 'sha256',
        'ES256K' => 'sha256',
        'ES384' => 'sha384',
        'ES512' => 'sha512',
        'EdDSA' => 'sha512'
      }.freeze

      # @return [Symbol] the OIDC response scenario.
      attr_reader :flow

      def self.code(**options)
        new(:code, **options)
      end

      def self.implicit(**options)
        new(:implicit, **options)
      end

      def self.hybrid(**options)
        new(:hybrid, **options)
      end

      def self.for(flow, **options)
        new(flow, **options)
      end

      def self.build(configuration)
        return configuration if configuration.is_a?(Profile)
        raise ArgumentError, 'OIDC profile configuration must be a Hash' unless configuration.is_a?(Hash)

        options = configuration.dup
        options.transform_keys!(&:to_sym)
        flow = options.delete(:flow) || options.delete(:response_flow)
        new(flow, **options)
      end

      def initialize(flow = nil, response_flow: nil, nonce: nil, code: nil, access_token: nil,
                     client_id: nil, authorized_party: nil, audience: nil, algorithm: nil)
        @flow = resolve_flow(flow || response_flow)
        @expected_nonce = nonce
        @code = code
        @access_token = access_token
        @expected_audience = audience || client_id
        @expected_azp = authorized_party || client_id
        @algorithm = algorithm
      end

      def verify!(context:)
        algorithm = resolve_algorithm(context)
        payload = context.payload

        verify_nonce!(payload)
        verify_audience!(payload)
        verify_authorized_party!(payload)
        verify_code_hash!(payload, algorithm)
        verify_access_token_hash!(payload, algorithm)
        nil
      end

      private

      def resolve_flow(value)
        raise ArgumentError, 'OIDC flow is required' if value.nil?

        flow = value.to_s.gsub(/([a-z0-9])([A-Z])/, '\\1_\\2').tr('-', '_').downcase.to_sym
        return flow if FLOWS.include?(flow)

        raise ArgumentError, "OIDC flow must be one of #{FLOWS.join(', ')}"
      end

      def resolve_algorithm(context)
        algorithm = @algorithm
        algorithm ||= context.verified_algorithm if context.respond_to?(:verified_algorithm)
        algorithm = algorithm.alg if algorithm.respond_to?(:alg)
        algorithm = algorithm.to_s.upcase

        if algorithm.empty?
          raise JWT::IncorrectAlgorithm, 'The verified JWS algorithm is required for OIDC hash verification'
        end

        HASH_ALGORITHMS.fetch(algorithm) do
          raise JWT::IncorrectAlgorithm, "Cannot determine OIDC hash algorithm for JWS alg #{algorithm}"
        end
      end

      def verify_nonce!(payload)
        return unless require_nonce? || !@expected_nonce.nil?

        nonce = payload['nonce']
        raise JWT::MissingRequiredClaim, 'Missing required claim nonce' if nonce.nil?
        raise JWT::InvalidNonceError, "Invalid nonce. Received #{nonce}" unless nonce.is_a?(String)
        return if @expected_nonce.nil?

        unless secure_equal?(@expected_nonce.to_s, nonce)
          raise JWT::InvalidNonceError, "Invalid nonce. Expected #{@expected_nonce}, received #{nonce}"
        end
      end

      def verify_audience!(payload)
        return if @expected_audience.nil?

        Claims::Audience.new(expected_audience: @expected_audience).verify!(context: Claims::VerificationContext.new(payload: payload))
      end

      def verify_authorized_party!(payload)
        audience = payload['aud']
        azp = payload['azp']

        audiences = Array(audience)
        return unless audiences.length > 1 || (!azp.nil? && !@expected_azp.nil?)
        raise JWT::InvalidAzpError, 'Missing required claim azp for multiple audiences' if azp.nil?
        raise JWT::InvalidAzpError, 'Expected authorized party must be provided to verify azp' if @expected_azp.nil? && audiences.length > 1

        unless azp.is_a?(String) && secure_equal?(@expected_azp.to_s, azp)
          raise JWT::InvalidAzpError, "Invalid authorized party. Expected #{@expected_azp}, received #{azp}"
        end
      end

      def verify_code_hash!(payload, digest_algorithm)
        verify_hash!(
          claim: 'c_hash',
          value: @code,
          hash: payload['c_hash'],
          required: flow == :hybrid,
          forbidden: flow == :implicit,
          digest_algorithm: digest_algorithm,
          error_class: JWT::InvalidCHashError
        )
      end

      def verify_access_token_hash!(payload, digest_algorithm)
        verify_hash!(
          claim: 'at_hash',
          value: @access_token,
          hash: payload['at_hash'],
          required: !@access_token.nil? && flow != :code,
          forbidden: false,
          digest_algorithm: digest_algorithm,
          error_class: JWT::InvalidAtHashError
        )
      end

      def verify_hash!(claim:, value:, hash:, required:, forbidden:, digest_algorithm:, error_class:)
        present = !hash.nil?
        raise error_class, "Unexpected #{claim} claim for #{flow} flow" if present && forbidden
        raise JWT::MissingRequiredClaim, "Missing required claim #{claim}" if required && !present
        return unless present

        unless value.is_a?(String)
          raise ArgumentError, "Expected value for #{claim} verification must be provided"
        end
        return if hash.is_a?(String) && valid_base64url?(hash) && secure_equal?(left_hash(value, digest_algorithm), JWT::Base64.url_decode(hash))

        raise error_class, "Invalid #{claim}"
      end

      def require_nonce?
        flow == :implicit || flow == :hybrid
      end

      def left_hash(value, digest_algorithm)
        digest = OpenSSL::Digest.digest(digest_algorithm, value.to_s)
        digest.byteslice(0, digest.bytesize / 2)
      end

      def valid_base64url?(value)
        return false if value.empty? || value.include?('=')

        JWT::Base64.url_decode(value)
        true
      rescue JWT::Base64DecodeError
        false
      end

      def secure_equal?(expected, actual)
        return false unless expected.bytesize == actual.bytesize

        if OpenSSL.respond_to?(:fixed_length_secure_compare)
          OpenSSL.fixed_length_secure_compare(expected.b, actual.b)
        else
          result = 0
          expected.bytes.each_with_index { |byte, index| result |= byte ^ actual.bytes[index] }
          result.zero?
        end
      rescue ArgumentError
        false
      end
    end
  end
end
