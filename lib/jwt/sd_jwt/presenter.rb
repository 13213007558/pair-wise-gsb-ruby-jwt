# frozen_string_literal: true

module JWT
  module SDJWT
    # Builds an SD-JWT presentation (RFC 9901 section 4.2): the holder selects a
    # subset of the issuer's disclosures and optionally adds a Key Binding JWT.
    class Presenter
      # @param sd_jwt [CompoundSdJwt] the SD-JWT received from the issuer.
      def initialize(sd_jwt)
        @sd_jwt = sd_jwt
      end

      # Selects disclosures by the paths they were made disclosable with, for
      # example +['name', 'address.street', 'nationalities[0]']+.
      #
      # @param paths [Array<String>] the claim paths to present.
      # @return [CompoundSdJwt] a new SD-JWT containing only the selected disclosures.
      # @raise [JWT::SDJWTFormatError] if a path does not correspond to a disclosure.
      def present(paths)
        wanted = Array(paths).map { |path| Issuer.parse_path(path) }.uniq

        selected = @sd_jwt.disclosures.select do |disclosure|
          wanted.include?(digest_paths[disclosure.digest])
        end

        if selected.length != wanted.length
          known = digest_paths.values.map { |path| self.class.format_path(path) }
          unknown = Array(paths).reject { |path| known.include?(path) }
          raise JWT::SDJWTFormatError, "No disclosure found for path(s): #{unknown.join(', ')}"
        end

        CompoundSdJwt.new(issuer_jwt: @sd_jwt.issuer_jwt, disclosures: selected)
      end

      # Adds a Key Binding JWT to the presentation (RFC 9901 section 4.3).
      #
      # @param presentation [CompoundSdJwt] the presentation returned by {#present}.
      # @param audience [String, Array<String>] the expected verifier audience.
      # @param nonce [String] the nonce provided by the verifier.
      # @param key [String, OpenSSL::PKey::PKey, JWT::JWK::KeyBase] the holder's private key.
      # @param algorithm [String, Object, nil] the signing algorithm. Inferred
      #   from the key/JWK when omitted.
      # @param iat [Integer] issued at time, defaults to the current time.
      # @return [CompoundSdJwt] the presentation carrying the Key Binding JWT.
      def bind(presentation, audience:, nonce:, key:, algorithm: nil, iat: ::Time.now.to_i)
        cnf = @sd_jwt.unverified_payload['cnf']
        unless cnf.is_a?(::Hash) && cnf['jwk'].is_a?(::Hash)
          raise JWT::SDJWTFormatError, 'Issuer JWT does not contain a holder public key (cnf.jwk)'
        end

        resolved_algorithm = algorithm || infer_algorithm(key)
        sd_hash = Digestable.new(@sd_jwt.unverified_payload['_sd_alg']).digest(sd_jwt_prefix(presentation))

        header = { 'typ' => 'kb+jwt' }
        kb_payload = {
          'iat' => iat,
          'aud' => audience,
          'nonce' => nonce,
          'sd_hash' => sd_hash
        }

        kb_token = ::JWT::Token.new(payload: kb_payload, header: header)
        kb_token.verify_claims!(:numeric)
        kb_token.sign!(algorithm: resolved_algorithm, key: key)

        presentation.kb_jwt = kb_token.jwt
        presentation
      end

      # @param path [Array<String, Integer>] the parsed path.
      # @return [String] the path as accepted by {#present} and {Issuer}.
      def self.format_path(path)
        path.map.with_index do |component, idx|
          if component.is_a?(::Integer)
            "[#{component}]"
          elsif idx.zero?
            component
          else
            ".#{component}"
          end
        end.join
      end

      private

      # The SD-JWT prefix the "sd_hash" is computed over: issuer JWT and the
      # presented disclosures, terminated with "~" and without a KB JWT.
      def sd_jwt_prefix(presentation)
        CompoundSdJwt.new(issuer_jwt: presentation.issuer_jwt,
                          disclosures: presentation.disclosures).to_s
      end

      def infer_algorithm(key)
        return key.jwa if key.respond_to?(:jwa)

        case key
        when ::OpenSSL::PKey::EC
          ::JWT::JWA::Ecdsa.curve_by_name(key.group.curve_name)[:algorithm]
        when ::OpenSSL::PKey::RSA
          'RS256'
        when ::String
          'HS256'
        else
          raise JWT::SDJWTFormatError, 'Could not infer the Key Binding JWT algorithm, please specify it'
        end
      end

      # Maps each disclosure digest to the path of the claim it discloses. The
      # claim name of object member disclosures is taken from the disclosure
      # itself, only the parent location is visible in the issuer JWT.
      def digest_paths
        @digest_paths ||= begin
          by_digest = @sd_jwt.disclosures.to_h { |disclosure| [disclosure.digest, disclosure] }
          paths = {}
          collect_paths(@sd_jwt.unverified_payload, [], by_digest, paths)
          paths
        end
      end

      def collect_paths(value, current_path, by_digest, paths)
        case value
        when ::Hash
          value['_sd']&.each do |digest|
            disclosure = by_digest[digest]
            if disclosure && !disclosure.claim_name.nil?
              paths[digest] = current_path + [disclosure.claim_name]
            end
          end

          value.each do |key, child|
            next if key == '_sd'

            collect_paths(child, current_path + [key], by_digest, paths)
          end
        when ::Array
          value.each_with_index do |element, index|
            if element.is_a?(::Hash) && element.key?('...')
              paths[element['...']] = current_path + [index]
            else
              collect_paths(element, current_path + [index], by_digest, paths)
            end
          end
        end
      end
    end
  end
end
