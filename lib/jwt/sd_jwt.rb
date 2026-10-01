# frozen_string_literal: true

require_relative 'sd_jwt/digestable'
require_relative 'sd_jwt/disclosure'
require_relative 'sd_jwt/compound_sd_jwt'
require_relative 'sd_jwt/issuer'
require_relative 'sd_jwt/presenter'
require_relative 'sd_jwt/verification_result'
require_relative 'sd_jwt/verifier'

module JWT
  # Selective Disclosure for JWTs (RFC 9901, "SD-JWT").
  #
  # This module groups the SD-JWT issuance, holder presentation and verifier
  # APIs. All signing and signature verification reuses the existing algorithm
  # ({JWT::JWA}) and key ({JWT::JWK}) interfaces.
  #
  # Issuing a credential with selectively disclosable claims:
  #
  #   sd_jwt = JWT::SDJWT.issue(
  #     claims: { name: 'Alice', age: 42, address: { street: 'Main St' } },
  #     disclosable: ['name', 'age', 'address.street'],
  #     key: issuer_key, algorithm: 'ES256'
  #   )
  #
  # A holder presents a subset of the disclosures:
  #
  #   presentation = JWT::SDJWT.present(sd_jwt, ['name'])
  #
  # The verifier receives only the claims that were actually disclosed:
  #
  #   result = JWT::SDJWT.verify(presentation, key: issuer_public_key, algorithm: 'ES256')
  #   result.claims # => {'name' => 'Alice'}
  module SDJWT
    class << self
      # Issues an SD-JWT, see {Issuer#initialize} for the full list of options.
      #
      # @return [CompoundSdJwt] the issuer signed SD-JWT with all disclosures.
      def issue(**options)
        Issuer.new(**options).issue
      end

      # Selects disclosures for presentation, see {Presenter#present}.
      #
      # @return [CompoundSdJwt] the presentation without a Key Binding JWT.
      def present(sd_jwt, paths)
        Presenter.new(parse(sd_jwt)).present(paths)
      end

      # Adds a Key Binding JWT to a presentation, see {Presenter#bind}.
      #
      # @return [CompoundSdJwt] the presentation with a Key Binding JWT.
      def bind(sd_jwt, presentation: nil, **options)
        source = parse(sd_jwt)
        presenter = Presenter.new(source)
        target = presentation ? parse(presentation) : CompoundSdJwt.new(
          issuer_jwt: source.issuer_jwt, disclosures: source.disclosures
        )
        presenter.bind(target, **options)
      end

      # Verifies an SD-JWT presentation, see {Verifier#initialize}.
      #
      # @return [VerificationResult] the verification result.
      def verify(serialized_sd_jwt, **options)
        Verifier.new(serialized_sd_jwt, **options).verify
      end

      # Parses a serialized SD-JWT without any verification.
      #
      # @return [CompoundSdJwt]
      def parse(serialized_sd_jwt)
        return serialized_sd_jwt if serialized_sd_jwt.is_a?(CompoundSdJwt)

        CompoundSdJwt.parse(serialized_sd_jwt)
      end
    end
  end
end
