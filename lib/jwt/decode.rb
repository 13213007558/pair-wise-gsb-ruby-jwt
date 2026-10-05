# frozen_string_literal: true

require 'json'
require 'jwt/x5c_key_finder'

module JWT
  # The Decode class is responsible for decoding and verifying JWT tokens.
  class Decode
    # Order is very important - first check for string keys, next for symbols
    ALGORITHM_KEYS = ['algorithm',
                      :algorithm,
                      'algorithms',
                      :algorithms].freeze

    # Initializes a new decoder.
    #
    # @param jwt [String] the JWS or compact JWE to decode.
    # @param key [Object] the signature verification or JWE decryption key.
    # @param verify [Boolean] whether to apply the configured verification policies.
    # @param options [Hash] decoding, JWE, nested JWS, and claim options.
    # @param keyfinder [Proc] optional dynamic key lookup callback.

    def initialize(jwt, key, verify, options, &keyfinder)
      raise JWT::MalformedTokenError, 'Nil JSON web token' unless jwt

      @jwt = jwt
      @key = key
      @options = options
      @verify = verify
      @keyfinder = keyfinder
      @jwe_token = nil
      @token = nil
    end

    # Decodes the token after applying all explicitly configured verification
    # or authenticated decryption policies.
    #
    # @return [Array<Hash>] the payload and one or more token headers.

    def decode_segments
      return decode_jwe_segments if jwe_token?

      validate_segment_count!
      if @verify
        verify_algo
        set_key
        verify_signature
        Claims::DecodeVerifier.verify!(token.unverified_payload, @options)
      end

      [token.unverified_payload, token.header]
    end

    private

    attr_reader :token

    def jwe_token
      @jwe_token ||= JWE::CompactToken.new(@jwt)
    end

    def decode_jwe_segments
      verify_jwe_algorithms!
      jwe_token.decrypt(
        key: jwe_decryption_key,
        algorithms: jwe_algorithms,
        encryption_algorithms: jwe_encryption_algorithms
      )

      nested_token = nested_jws?
      return decode_nested_jwe(nested_token) if nested_token

      payload = parse_decrypted_payload
      Claims::DecodeVerifier.verify!(payload, @options) if @verify
      [payload, jwe_token.header]
    rescue ::JSON::ParserError, EncodingError
      raise JWT::MalformedTokenError, 'Invalid JWE payload encoding'
    end

    def verify_jwe_algorithms!
      raise JWT::IncorrectAlgorithm, 'A JWE key management algorithm must be specified' if jwe_algorithms.empty?
      raise JWT::IncorrectAlgorithm, 'A JWE content encryption algorithm must be specified' if jwe_encryption_algorithms.empty?
    end

    def jwe_algorithms
      Array(option(:jwe_algorithms,
                 :jwe_algorithm,
                 'jwe_algorithms',
                 'jwe_algorithm',
                 :encryption_algorithms,
                 :encryption_algorithm,
                 'encryption_algorithms',
                 'encryption_algorithm'))
    end

    def jwe_encryption_algorithms
      Array(option(:jwe_encryption_algorithms,
                 :jwe_encryption_algorithm,
                 'jwe_encryption_algorithms',
                 'jwe_encryption_algorithm',
                 :encryption_methods,
                 :encryption_method,
                 'encryption_methods',
                 'encryption_method'))
    end

    def jwe_token?
      @jwt.count('.') == JWE::CompactToken::SEGMENT_COUNT - 1
    end

    def jwe_decryption_key
      return @key unless @keyfinder

      key = @keyfinder.call(jwe_token.header)
      return key if key && !Array(key).empty?

      raise JWT::DecodeError, 'No decryption key available'
    end

    def nested_jws?
      plaintext = jwe_token.plaintext
      return unless plaintext.count('.') == 2

      segments = plaintext.split('.')
      return unless segments.all? { |segment| segment =~ /\A[A-Za-z0-9_-]*\z/ }

      header = JWT::JSON.parse(::JWT::Base64.url_decode(segments.first))
      return unless header.is_a?(Hash) && header['alg'].is_a?(String)

      EncodedToken.new(plaintext)
    rescue JWT::Error, ::JSON::ParserError, ArgumentError
      nil
    end

    def decode_nested_jwe(nested_token)
      policy = nested_signature_policy
      allowed_algorithms = policy[:algorithms].map(&:to_s)
      if @verify
        raise JWT::IncorrectAlgorithm, 'An independent JWS algorithm must be specified for nested tokens' if allowed_algorithms.empty?
        raise JWT::IncorrectAlgorithm, 'Expected a different algorithm' unless allowed_algorithms.include?(nested_token.header['alg'].to_s)
      end

      if @verify
        nested_token.verify_signature!(**nested_signature_options(policy))
        Claims::DecodeVerifier.verify!(nested_token.unverified_payload, @options)
      end

      [nested_token.unverified_payload, nested_token.header, jwe_token.header]
    end

    def nested_signature_options(policy)
      options = { algorithm: policy[:algorithms] }
      if policy[:key_finder]
        options[:key_finder] = policy[:key_finder]
      else
        options[:key] = policy[:key]
      end
      options
    end

    def nested_signature_policy
      policy = option(:nested_signature, :jws, 'nested_signature', 'jws') || {}
      policy = policy.transform_keys(&:to_sym) if policy.is_a?(Hash)
      {
        algorithms: Array(policy[:algorithms] || policy[:algorithm] ||
                          option(:jws_algorithms, :jws_algorithm, 'jws_algorithms', 'jws_algorithm',
                                 :signature_algorithms, :signature_algorithm,
                                 'signature_algorithms', 'signature_algorithm')),
        key: policy[:key] || option(:jws_key, 'jws_key', :signature_key, 'signature_key'),
        key_finder: policy[:key_finder] ||
                    option(:jws_key_finder, 'jws_key_finder', :signature_key_finder, 'signature_key_finder') ||
                    nil
      }
    end

    def option(*keys)
      keys.each do |key|
        return @options[key] if @options.key?(key)
      end
      nil
    end

    def parse_decrypted_payload
      JWT::JSON.parse(jwe_token.plaintext)
    end

    def token
      @token ||= EncodedToken.new(@jwt)
    end

    def verify_signature
      return if none_algorithm?

      raise JWT::SignatureError, 'No verification key available' unless @key

      token.verify_signature!(algorithm: allowed_and_valid_algorithms, key: @key)
    end

    def verify_algo
      raise JWT::IncorrectAlgorithm, 'An algorithm must be specified' if allowed_algorithms.empty?
      raise JWT::MalformedTokenError, 'Token header not a JSON object' unless valid_token_header?
      raise JWT::IncorrectAlgorithm, 'Token is missing alg header' unless alg_in_header
      raise JWT::IncorrectAlgorithm, 'Expected a different algorithm' if allowed_and_valid_algorithms.empty?
    end

    def set_key
      @key = find_key(&@keyfinder) if @keyfinder
      if @options[:jwks]
        @key = ::JWT::JWK::KeyFinder.new(
          jwks: @options[:jwks],
          allow_nil_kid: @options[:allow_nil_kid],
          key_fields: @options[:key_fields]
        ).call(token)
      end

      return unless (x5c_options = @options[:x5c])

      @key = X5cKeyFinder.new(x5c_options[:root_certificates], x5c_options[:crls]).from(token.header['x5c'])
    end

    def allowed_and_valid_algorithms
      @allowed_and_valid_algorithms ||= allowed_algorithms.select { |alg| alg.valid_alg?(alg_in_header) }
    end

    def given_algorithms
      alg_key = ALGORITHM_KEYS.find { |key| @options[key] }
      Array(@options[alg_key])
    end

    def allowed_algorithms
      @allowed_algorithms ||= given_algorithms.map { |alg| JWA.resolve(alg) }
    end

    def find_key(&keyfinder)
      key = (keyfinder.arity == 2 ? yield(token.header, token.unverified_payload) : yield(token.header))
      return key if key && !Array(key).empty?

      raise JWT::SignatureError, 'No verification key available'
    end

    def validate_segment_count!
      segment_count = @jwt.count('.') + 1
      return if segment_count == 3
      return if !@verify && segment_count == 2
      return if segment_count == 2 && none_algorithm?

      raise JWT::MalformedTokenError, 'Not enough or too many segments'
    end

    def none_algorithm?
      valid_token_header? && alg_in_header == 'none'
    end

    def valid_token_header?
      token.header.is_a?(Hash)
    end

    def alg_in_header
      token.header['alg']
    end
  end
end
