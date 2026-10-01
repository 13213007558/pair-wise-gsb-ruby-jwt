# frozen_string_literal: true

require_relative 'key_filter'

module JWT
  module JWK
    # JSON Web Key keyfinder
    # To find the key for a given kid
    class KeyFinder
      # Initializes a new KeyFinder instance.
      # @param [Hash] options the options to create a KeyFinder with
      # @option options [Proc, JWT::JWK::Set] :jwks the jwks or a loader proc
      # @option options [Boolean] :allow_nil_kid whether to allow nil kid
      # @option options [Array] :key_fields the fields to use for key matching,
      #                         the order of the fields are used to determine
      #                         the priority of the keys.
      # @option options [JWT::JWK::KeyFilter, Hash, #call] :key_filter a server
      #                         side key selection strategy. When given, the
      #                         matching keys are jointly checked against the
      #                         algorithm, kty, use, key_ops and an optional
      #                         thumbprint whitelist. Exactly one key must
      #                         survive the filtering, otherwise an error is
      #                         raised (the first key is never silently picked,
      #                         making the result independent of the key order
      #                         in the JWKS).
      def initialize(options)
        @allow_nil_kid = options[:allow_nil_kid]
        jwks_or_loader = options[:jwks]

        @jwks_loader = if jwks_or_loader.respond_to?(:call)
                         jwks_or_loader
                       else
                         ->(_options) { jwks_or_loader }
                       end

        @key_fields = options[:key_fields] || %i[kid]
        @key_filter = build_key_filter(options[:key_filter])
      end

      # Returns the verification key for the given kid
      # @param [String] kid the key id
      def key_for(kid, key_field = :kid, header = {})
        raise ::JWT::MalformedTokenError, "Invalid type for #{key_field} header parameter" unless kid.nil? || kid.is_a?(String)

        jwk = resolve_key(kid, key_field, header)

        raise ::JWT::SignatureError, 'No keys found in jwks' unless @jwks.any?
        raise ::JWT::SignatureError, "Could not find public key for kid #{kid}" unless jwk

        jwk.verify_key
      end

      # Returns the key for the given token
      # @param [JWT::EncodedToken] token the token
      def call(token)
        @key_fields.each do |key_field|
          field_value = token.header[key_field.to_s]

          return key_for(field_value, key_field, token.header) if field_value
        end

        raise ::JWT::SignatureError, 'No key id (kid) or x5t found from token headers' unless @allow_nil_kid

        kid = token.header['kid']
        key_for(kid, :kid, token.header)
      end

      private

      def build_key_filter(filter)
        case filter
        when nil  then nil
        when Hash then KeyFilter.new(**filter.transform_keys(&:to_sym))
        else filter
        end
      end

      def resolve_key(kid, key_field, header)
        key_matcher = ->(key) { (kid.nil? && @allow_nil_kid) || key[key_field] == kid }

        # First try without invalidation to facilitate application caching
        @jwks ||= JWT::JWK::Set.new(@jwks_loader.call(key_field => kid))
        jwk = select_key(@jwks, key_matcher, kid, key_field, header)

        return jwk if jwk

        # Second try, invalidate for backwards compatibility
        @jwks = JWT::JWK::Set.new(@jwks_loader.call(invalidate: true, kid_not_found: true, key_field => kid))
        select_key(@jwks, key_matcher, kid, key_field, header)
      end

      def select_key(jwks, key_matcher, kid, key_field, header)
        matches = jwks.select { |key| key_matcher.call(key) }
        matches = filter_keys(matches, header)

        return nil if matches.empty?
        return matches.first if matches.one? || !@key_filter

        raise ::JWT::JWKError, "Multiple keys found in jwks for #{key_field} #{kid}"
      end

      def filter_keys(matches, header)
        return matches unless @key_filter

        if @key_filter.respond_to?(:select)
          @key_filter.select(matches, algorithm: header['alg'] || header[:alg])
        else
          matches.select { |key| @key_filter.call(key, header) }
        end
      end
    end
  end
end
