# frozen_string_literal: true

require_relative 'sd_jwt/constants'
require_relative 'sd_jwt/hasher'
require_relative 'sd_jwt/disclosure'
require_relative 'sd_jwt/issuer'
require_relative 'sd_jwt/presentation'
require_relative 'sd_jwt/key_binding'
require_relative 'sd_jwt/verifier'

module JWT
  # Selective Disclosure JWT support, implementing RFC 9901.
  #
  # This module groups the pieces needed to issue, present and verify
  # SD-JWTs. The signing and signature verification of both the issuer JWT and
  # the optional Key Binding JWT reuse the existing algorithms and key
  # interfaces ({JWT::JWA}, {JWT::JWK}).
  module SDJWT
    class << self
      # Issues a new SD-JWT.
      #
      # @example
      #   issued = JWT::SDJWT.issue(
      #     { name: 'Alice', age: 42, address: { country: 'US' } },
      #     key: private_key,
      #     algorithm: 'ES256'
      #   ) do |issuer|
      #     issuer.disclose(:name)
      #     issuer.disclose('address', :country)
      #   end
      #
      # @param payload [Hash] the full claims of the credential.
      # @param key [Object] the issuer signing key.
      # @param algorithm [String] the JWS algorithm.
      # @param hash_algorithm [String] the `_sd_alg` hash algorithm.
      # @param header_fields [Hash] additional JWS header fields.
      # @yieldparam issuer [Issuer] the issuer, to mark disclosable claims.
      # @return [IssuedCredential]
      def issue(payload, key:, algorithm: 'HS256', hash_algorithm: DEFAULT_HASH_ALGORITHM, header_fields: {}, &block)
        issuer = Issuer.new(payload, hash_algorithm: hash_algorithm)
        block&.call(issuer)
        issuer.issue!(key: key, algorithm: algorithm, header_fields: header_fields)
      end

      # Builds a holder presentation from an issued credential.
      #
      # @example present the name and the whole address object
      #   presentation = JWT::SDJWT.present(issued, :name, %w[address])
      #
      # @example present only the country nested inside the address
      #   presentation = JWT::SDJWT.present(issued, %w[address country])
      #
      # @param issued [IssuedCredential, String] the credential issued by {.issue},
      #   or an already combined issuer-SD-JWT string.
      # @param disclosed [Array<Disclosure, Symbol, String, Integer, Array>] the
      #   disclosures to release. Each argument is either a {Disclosure}, a path
      #   given as multiple segments (`:name`, `['address', 'country']`), or a
      #   path wrapped with `:subtree` (`[['address', 'geo'], :subtree]`) which
      #   also includes every disclosure nested below that claim.
      # @return [Presentation]
      def present(issued, *disclosed)
        credential = issued if issued.is_a?(IssuedCredential)
        jwt = credential ? credential.jwt : issued.to_s.split(SEPARATOR).first

        presentation = Presentation.new(jwt)
        disclosed.each { |entry| add_disclosure(presentation, credential, entry) }
        presentation
      end

      # Verifies an SD-JWT presentation. See {Verifier#verify!} for the options.
      #
      # @param serialized [Presentation, String] the presentation to verify.
      # @return [VerifiedPresentation]
      def verify(serialized, **options, &key_finder)
        verifier = Verifier.new(serialized)
        options[:key_finder] = key_finder if key_finder
        verifier.verify!(**options)
      end

      # Computes the `sd_hash` for a presentation (RFC 9901 section 4.3).
      #
      # @param presentation [Presentation] the presentation.
      # @param hash_algorithm [String] the hash algorithm.
      # @return [String]
      def sd_hash(presentation, hash_algorithm = DEFAULT_HASH_ALGORITHM)
        KeyBinding.sd_hash(presentation.jwt, presentation.disclosures, hash_algorithm)
      end

      # Signs a Key Binding JWT for a presentation. See {KeyBinding.sign}.
      #
      # @return [String] the signed Key Binding JWT.
      def bind_key(presentation, key:, audience:, nonce:, algorithm:, **options)
        kb = KeyBinding.sign(presentation: presentation, key: key, audience: audience,
                             nonce: nonce, algorithm: algorithm, **options)
        presentation.key_binding_jwt = kb
        kb
      end

      private

      # Adds a single disclosure addressed by its exact path. It does not pull
      # in nested disclosures: the holder selects each claim it wants to reveal
      # explicitly. Passing `[:subtree]` as the last path segment selects the
      # claim and every disclosure nested below it.
      def add_disclosure(presentation, credential, entry)
        if entry.is_a?(Disclosure)
          presentation.add(entry)
        elsif credential
          resolve_path(credential, Array(entry)).each { |disclosure| presentation.add(disclosure) }
        else
          raise ::JWT::SDJWTError, "Cannot resolve disclosure path #{entry.inspect} without an IssuedCredential"
        end
      end

      def resolve_path(credential, path)
        path = path.flatten
        subtree = path.last == :subtree
        target = subtree ? path[0...-1] : path
        normalized = target.map { |segment| segment.is_a?(::Symbol) ? segment.to_s : segment }

        matching = credential.disclosures.select do |disclosure|
          next false unless disclosure.path

          if subtree
            disclosure.path.first(normalized.length) == normalized
          else
            disclosure.path == normalized
          end
        end

        if matching.empty?
          raise ::JWT::SDJWTError, "No disclosure found at path #{normalized.inspect}"
        end

        matching.sort_by { |disclosure| disclosure_path_sort_key(disclosure.path) }
      end

      def disclosure_path_sort_key(path)
        path.map { |segment| [segment.is_a?(::Integer) ? 1 : 0, segment.is_a?(::Integer) ? segment : segment.to_s] }
      end
    end
  end
end
