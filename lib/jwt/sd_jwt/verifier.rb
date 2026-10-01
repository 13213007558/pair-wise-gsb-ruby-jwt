# frozen_string_literal: true

require_relative 'constants'
require_relative 'disclosure'
require_relative 'key_binding'
require_relative 'presentation'

module JWT
  module SDJWT
    # Result of a successful SD-JWT verification.
    class VerifiedPresentation
      # @return [Hash] exactly the claims that were disclosed and verified.
      attr_reader :claims

      # @return [Hash] the header of the issuer JWT.
      attr_reader :header

      # @return [Array<Disclosure>] the disclosures referenced by the SD-JWT.
      attr_reader :disclosures

      # @return [Hash, nil] the verified Key Binding JWT claims, if present.
      attr_reader :key_binding

      # @param claims [Hash] the disclosed claims.
      # @param header [Hash] the issuer JWT header.
      # @param disclosures [Array<Disclosure>] the referenced disclosures.
      # @param key_binding [Hash, nil] the Key Binding JWT claims.
      def initialize(claims:, header:, disclosures:, key_binding: nil)
        @claims = claims
        @header = header
        @disclosures = disclosures
        @key_binding = key_binding
      end

      # @return [Array(Hash, Hash)] the disclosed claims and the issuer JWT header.
      def to_a
        [claims, header]
      end
    end

    # Verifies SD-JWT presentations according to RFC 9901 section 6.
    #
    # @example
    #   result = JWT::SDJWT::Verifier.new(serialized).verify!(
    #     key: issuer_public_key,
    #     algorithms: ['ES256']
    #   )
    #   result.claims # => only the claims the holder chose to disclose
    class Verifier
      # @param serialized [Presentation, String] the presentation to verify.
      def initialize(serialized)
        @presentation = serialized.is_a?(Presentation) ? serialized : Presentation.parse(serialized)
      end

      # @return [Presentation] the parsed presentation.
      attr_reader :presentation

      # Verifies the presentation and returns the disclosed claims.
      #
      # @param key [Object] the issuer JWS verification key.
      # @param algorithms [Array<String>, nil] acceptable issuer JWS algorithms.
      #   Defaults to the `alg` header of the issuer JWT.
      # @param key_finder [#call, nil] dynamic key finder for the issuer JWT.
      # @param claims [Array, Hash, nil] registered claim verifications applied to
      #   the disclosed claims (same options as `JWT::Token#verify_claims!`).
      # @param expected_audience [String, Array<String>, nil] required `aud` and
      #   nonce for the Key Binding JWT.
      # @param expected_nonce [String, nil] expected Key Binding nonce.
      # @param kb_algorithms [Array<String>] acceptable Key Binding algorithms.
      # @param iat_leeway [Integer] leeway in seconds for the KB-JWT `iat` check.
      # @return [VerifiedPresentation]
      # @raise [JWT::SDJWTVerificationError] if the presentation is invalid.
      def verify!(key: nil, algorithms: nil, key_finder: nil, claims: nil,
                  expected_audience: nil, expected_nonce: nil, kb_algorithms: nil, iat_leeway: 0)
        encoded_token = verify_issuer_jwt(key, algorithms, key_finder)
        payload = issuer_payload(encoded_token)
        hash_algorithm = verify_sd_alg(payload)

        disclosed_claims, disclosures = resolve_disclosures(payload, hash_algorithm)
        verify_registered_claims(encoded_token, disclosed_claims, claims) if claims

        key_binding_claims = verify_key_binding(payload, hash_algorithm,
                                                expected_audience, expected_nonce,
                                                kb_algorithms, iat_leeway)

        VerifiedPresentation.new(
          claims: disclosed_claims,
          header: encoded_token.header,
          disclosures: disclosures,
          key_binding: key_binding_claims
        )
      end

      def resolve_disclosures(payload, hash_algorithm)
        digest_map = index_disclosures(hash_algorithm)
        @seen_digests = {}
        @used_disclosures = []

        disclosed_claims = process_object(payload, digest_map, root: true)
        strip_hidden_claims(disclosed_claims)
        disclosed_claims.delete(SD_ALG_KEY)

        ensure_all_disclosures_referenced!(digest_map)
        [disclosed_claims, @used_disclosures]
      end

      # Like {#verify!} but returns `nil` instead of raising on failure.
      #
      # @return [VerifiedPresentation, nil]
      def verify(**kwargs)
        verify!(**kwargs)
      rescue ::StandardError
        nil
      end

      # @return [Boolean] whether the presentation verifies successfully.
      def valid?(**kwargs)
        !verify(**kwargs).nil?
      end

      private

      def issuer_payload(encoded_token)
        payload = encoded_token.unverified_payload
        unless payload.is_a?(::Hash)
          raise ::JWT::SDJWTVerificationError, 'Issuer JWT payload must be a JSON object'
        end

        payload
      end

      def ensure_all_disclosures_referenced!(digest_map)
        return if digest_map.empty?

        raise ::JWT::SDJWTUnreferencedDisclosureError,
              "#{digest_map.size} disclosure(s) are not referenced by any digest"
      end

      def verify_issuer_jwt(key, algorithms, key_finder)
        encoded_token = ::JWT::EncodedToken.new(presentation.jwt)

        alg = encoded_token.header.is_a?(::Hash) ? encoded_token.header['alg'] : nil
        raise ::JWT::SDJWTVerificationError, 'Issuer JWT header must be a JSON object' unless encoded_token.header.is_a?(::Hash)
        raise ::JWT::SDJWTVerificationError, 'Issuer JWT is missing the alg header' unless alg

        algorithms = Array(algorithms || alg)
        encoded_token.verify_signature!(algorithm: algorithms, key: key, key_finder: key_finder)
        encoded_token
      end

      def verify_sd_alg(payload)
        hash_algorithm = payload[SD_ALG_KEY] || DEFAULT_HASH_ALGORITHM
        if payload[SD_ALG_KEY] && !payload[SD_ALG_KEY].is_a?(::String)
          raise ::JWT::SDJWTVerificationError, "'#{SD_ALG_KEY}' must be a string"
        end
        unless Hasher::SUPPORTED_ALGORITHMS.include?(hash_algorithm)
          raise ::JWT::SDJWTVerificationError, "Unsupported SD-JWT hash algorithm '#{hash_algorithm}'"
        end

        hash_algorithm
      end

      def index_disclosures(hash_algorithm)
        map = {}
        presentation.disclosures.each do |disclosure|
          digest = disclosure.digest(hash_algorithm)
          if map.key?(digest)
            raise ::JWT::SDJWTDuplicateDigestError, 'The same digest/disclosure was provided more than once'
          end
          map[digest] = disclosure
        end
        map
      end

      def process_object(hash, digest_map, root: false)
        unless hash.is_a?(::Hash)
          raise ::JWT::SDJWTMalformedError, 'Expected a JSON object'
        end

        result = {}
        sd_digests = nil

        hash.each do |key, value|
          case key
          when SD_KEY
            unless value.is_a?(::Array) && value.all? { |entry| entry.is_a?(::String) }
              raise ::JWT::SDJWTMalformedError, "'#{SD_KEY}' must be an array of strings"
            end

            sd_digests = value
          when SD_ALG_KEY
            raise ::JWT::SDJWTInvalidNestingError, "'#{SD_ALG_KEY}' is only allowed in the root claim" unless root

            result[key] = value
          when ELLIPSIS
            raise ::JWT::SDJWTInvalidNestingError, "'#{ELLIPSIS}' is only allowed inside arrays"
          else
            result[key] = process_value(value, digest_map)
          end
        end

        result[SD_KEY] = apply_property_disclosures(sd_digests || [], result, digest_map)

        result
      end

      # Resolves the digests of hidden object properties. Digests for which no
      # disclosure was provided are kept verbatim in the `_sd` array: they
      # simply represent claims the holder chose not to reveal (RFC 9901 6.1).
      # The array is removed later by {#strip_hidden_claims}.
      #
      # @return [Array<String>] the still undisclosed digests.
      def apply_property_disclosures(sd_digests, result, digest_map)
        digests_seen_here = {}

        sd_digests.each_with_object([]) do |digest, remaining|
          ensure_string_digest(digest)
          ensure_unique_in_array!(digest, digests_seen_here)

          disclosure = digest_map[digest]
          unless disclosure
            remaining << digest # claim not disclosed in this presentation
            next
          end

          resolve_property_disclosure!(digest, disclosure, result, digest_map)
        end
      end

      def ensure_string_digest(digest)
        return if digest.is_a?(::String)

        raise ::JWT::SDJWTMalformedError, "'#{SD_KEY}' entries must be strings"
      end

      def ensure_unique_in_array!(digest, seen)
        return unless seen.key?(digest)

        raise ::JWT::SDJWTDuplicateDigestError, "Digest '#{digest}' is repeated in the same '#{SD_KEY}' array"
      ensure
        seen[digest] = true
      end

      def resolve_property_disclosure!(digest, disclosure, result, digest_map)
        register_digest(digest)
        digest_map.delete(digest)
        unless disclosure.property?
          raise ::JWT::SDJWTInvalidNestingError, 'An array element disclosure was referenced by an object'
        end
        if result.key?(disclosure.key)
          raise ::JWT::SDJWTClaimOverlapError,
                "Disclosed claim '#{disclosure.key}' overrides an existing claim of the issuer JWT"
        end

        @used_disclosures << disclosure
        result[disclosure.key] = process_value(disclosure.value, digest_map)
      end

      def process_value(value, digest_map)
        case value
        when ::Hash then process_object(value, digest_map)
        when ::Array then process_array(value, digest_map)
        else value
        end
      end

      def process_array(array, digest_map)
        array.each_with_object([]) do |element, result|
          if element.is_a?(::Hash) && element.key?(ELLIPSIS)
            process_array_placeholder(element, result, digest_map)
          elsif element == ELLIPSIS
            raise ::JWT::SDJWTInvalidNestingError, "'#{ELLIPSIS}' must be the only member of an array element object"
          else
            result << process_value(element, digest_map)
          end
        end
      end

      def process_array_placeholder(element, result, digest_map)
        unless element.length == 1
          raise ::JWT::SDJWTInvalidNestingError,
                "An array element containing '#{ELLIPSIS}' must not contain other members"
        end

        digest = element[ELLIPSIS]
        raise ::JWT::SDJWTMalformedError, "'#{ELLIPSIS}' must reference a digest string" unless digest.is_a?(::String)

        disclosure = digest_map[digest]
        return unless disclosure # undisclosed element is dropped (RFC 9901 6.1)

        register_digest(digest)
        digest_map.delete(digest)
        unless disclosure.array_element?
          raise ::JWT::SDJWTInvalidNestingError, 'An object property disclosure was referenced by an array'
        end

        @used_disclosures << disclosure
        result << process_value(disclosure.value, digest_map)
      end

      # Removes all traces of claims that were not disclosed in the
      # presentation: `_sd` arrays holding only remaining digests are deleted
      # from every object, and undisclosed array elements are dropped.
      def strip_hidden_claims(node)
        case node
        when ::Hash
          node.delete(SD_KEY) if node[SD_KEY].is_a?(::Array) && node[SD_KEY].all? { |entry| entry.is_a?(::String) }
          node.each_value { |value| strip_hidden_claims(value) }
        when ::Array
          node.each { |element| strip_hidden_claims(element) }
        end
      end

      def register_digest(digest)
        if @seen_digests.key?(digest)
          raise ::JWT::SDJWTDuplicateDigestError, "Digest '#{digest}' is referenced more than once"
        end
        @seen_digests[digest] = true
      end

      def verify_registered_claims(encoded_token, disclosed_claims, claims)
        token = ::JWT::Token.new(payload: disclosed_claims, header: encoded_token.header)
        token.verify_claims!(claims)
      end

      def verify_key_binding(issuer_payload, hash_algorithm, audience, nonce, algorithms, iat_leeway)
        return nil unless presentation.key_binding_jwt
        raise ::JWT::SDJWTKeyBindingError, 'Key Binding JWT requires an expected audience' unless audience
        raise ::JWT::SDJWTKeyBindingError, 'Key Binding JWT requires an expected nonce' unless nonce

        kwargs = {
          presentation: presentation,
          issuer_payload: issuer_payload,
          audience: audience,
          nonce: nonce,
          hash_algorithm: hash_algorithm,
          iat_leeway: iat_leeway
        }
        kwargs[:algorithms] = algorithms if algorithms

        KeyBinding.verify!(**kwargs)
      end
    end
  end
end
