# frozen_string_literal: true

require 'spec_helper'

RSpec.describe JWT::SDJWT::Verifier do
  let(:key) { 'issuer-secret' }
  let(:claims) do
    {
      'iss' => 'https://issuer.example',
      'name' => 'Alice',
      'address' => { 'country' => 'US', 'locality' => 'Springfield' },
      'nationalities' => %w[US DE]
    }
  end

  def issue!(&block)
    JWT::SDJWT::Issuer.new(claims).tap { |issuer| block&.call(issuer) }.issue!(key: key, algorithm: 'HS256')
  end

  describe '#verify!' do
    context 'with object member disclosure' do
      let(:issued) do
        issue! do |issuer|
          issuer.disclose('address', 'country', salt: 'salt-country')
          issuer.disclose('address', 'locality', salt: 'salt-locality')
        end
      end

      it 'returns the disclosed claim and hides the rest' do
        presentation = JWT::SDJWT.present(issued, ['address', 'country'])
        result = described_class.new(presentation.to_s).verify!(key: key, algorithms: ['HS256'])

        expect(result.claims['name']).to eq('Alice')
        expect(result.claims['address']).to eq('country' => 'US')
        expect(result.claims['address']).not_to have_key('locality')
        expect(result.claims).not_to have_key('_sd')
        expect(result.disclosures.map(&:key)).to eq(['country'])
      end

      it 'can reveal both members' do
        presentation = JWT::SDJWT.present(
          issued, ['address', 'country'], ['address', 'locality']
        )
        result = described_class.new(presentation.to_s).verify!(key: key, algorithms: ['HS256'])
        expect(result.claims['address']).to eq('country' => 'US', 'locality' => 'Springfield')
      end
    end

    context 'with array element disclosure' do
      let(:issued) do
        issue! do |issuer|
          issuer.disclose('nationalities', 0, salt: 'salt-us')
          issuer.disclose('nationalities', 1, salt: 'salt-de')
        end
      end

      it 'returns only the disclosed elements in original order' do
        presentation = JWT::SDJWT.present(issued, ['nationalities', 1])
        result = described_class.new(presentation.to_s).verify!(key: key, algorithms: ['HS256'])
        expect(result.claims['nationalities']).to eq(['DE'])
      end

      it 'returns both elements when both disclosures are presented' do
        presentation = JWT::SDJWT.present(
          issued, ['nationalities', 0], ['nationalities', 1]
        )
        result = described_class.new(presentation.to_s).verify!(key: key, algorithms: ['HS256'])
        expect(result.claims['nationalities']).to eq(%w[US DE])
      end
    end

    context 'with nested disclosure' do
      let(:claims) do
        {
          'address' => {
            'country' => 'US',
            'geo' => { 'lat' => 38.0, 'lon' => -97.0 }
          }
        }
      end

      let(:issued) do
        issue! do |issuer|
          issuer.disclose('address', 'country', salt: 'salt-country')
          issuer.disclose('address', 'geo', salt: 'salt-geo')
          issuer.disclose('address', 'geo', 'lat', salt: 'salt-lat')
          issuer.disclose('address', 'geo', 'lon', salt: 'salt-lon')
        end
      end

      it 'reveals a nested claim through the parent disclosure' do
        presentation = JWT::SDJWT.present(
          issued, ['address', 'geo'], ['address', 'geo', 'lat'], ['address', 'geo', 'lon']
        )
        result = described_class.new(presentation.to_s).verify!(key: key, algorithms: ['HS256'])
        expect(result.claims['address']['geo']).to eq('lat' => 38.0, 'lon' => -97.0)
      end

      it 'reveals only one nested member and hides the other' do
        presentation = JWT::SDJWT.present(
          issued, ['address', 'geo'], ['address', 'geo', 'lat']
        )
        result = described_class.new(presentation.to_s).verify!(key: key, algorithms: ['HS256'])
        expect(result.claims['address']['geo']).to eq('lat' => 38.0)
        expect(result.claims['address']['geo']).not_to have_key('lon')
      end

      it 'keeps undisclosed nested members hidden through unresolved digests' do
        # Rebuild with only lat nested, so omitting its disclosure leaves a _sd entry.
        nested_claims = { 'address' => { 'country' => 'US', 'geo' => { 'lat' => 38.0 } } }
        nested_issued = JWT::SDJWT::Issuer.new(nested_claims).tap do |issuer|
          issuer.disclose('address', 'country', salt: 'salt-country')
          issuer.disclose('address', 'geo', salt: 'salt-geo')
          issuer.disclose('address', 'geo', 'lat', salt: 'salt-lat')
        end.issue!(key: key, algorithm: 'HS256')

        presentation = JWT::SDJWT.present(nested_issued, ['address', 'geo'])
        result = described_class.new(presentation.to_s).verify!(key: key, algorithms: ['HS256'])
        expect(result.claims['address']).to eq('geo' => {})
        expect(result.claims['address']['geo']).not_to have_key('_sd')
      end

      it 'keeps the whole nested object hidden when its disclosure is omitted' do
        presentation = JWT::SDJWT.present(issued, ['address', 'country'])
        result = described_class.new(presentation.to_s).verify!(key: key, algorithms: ['HS256'])
        expect(result.claims['address']).to eq('country' => 'US')
      end
    end

    context 'signature verification' do
      let(:issued) { issue! { |i| i.disclose('name', salt: 's') } }

      it 'rejects a presentation signed with another key' do
        presentation = JWT::SDJWT.present(issued, 'name')
        expect do
          described_class.new(presentation.to_s).verify!(key: 'other-key', algorithms: ['HS256'])
        end.to raise_error(JWT::VerificationError)
      end

      it 'rejects an unexpected algorithm' do
        presentation = JWT::SDJWT.present(issued, 'name')
        expect do
          described_class.new(presentation.to_s).verify!(key: key, algorithms: ['RS256'])
        end.to raise_error(JWT::VerificationError)
      end

      it 'supports a key finder block through JWT::SDJWT.verify' do
        presentation = JWT::SDJWT.present(issued, 'name')
        result = JWT::SDJWT.verify(presentation.to_s, algorithms: ['HS256']) { |_header| key }
        expect(result.claims['name']).to eq('Alice')
      end
    end

    context 'malformed input' do
      let(:issued) { issue! { |i| i.disclose('name', salt: 's') } }
      let(:presentation) { JWT::SDJWT.present(issued, 'name') }

      it 'rejects non-string input' do
        expect { described_class.new(nil) }.to raise_error(JWT::SDJWTMalformedError)
      end

      it 'rejects a presentation without a valid issuer JWT' do
        expect { described_class.new('garbage~').verify!(key: key) }
          .to raise_error(JWT::SDJWTMalformedError)
      end

      it 'rejects a non-object issuer payload' do
        jwt = JWT.encode([1, 2, 3], key, 'HS256', { typ: 'sd-jwt' })
        expect { described_class.new(jwt).verify!(key: key, algorithms: ['HS256']) }
          .to raise_error(JWT::SDJWTVerificationError, /JSON object/)
      end
    end

    context 'duplicate digests' do
      let(:issued) { issue! { |i| i.disclose('name', salt: 's') } }

      it 'rejects the same disclosure provided twice' do
        presentation = JWT::SDJWT.present(issued, 'name')
        duplicated = "#{presentation.jwt}~#{presentation.disclosures.first.encoded}~#{presentation.disclosures.first.encoded}"
        expect { described_class.new(duplicated).verify!(key: key, algorithms: ['HS256']) }
          .to raise_error(JWT::SDJWTDuplicateDigestError)
      end

      it 'rejects the same digest referenced twice inside one _sd array' do
        d = JWT::SDJWT::Disclosure.property('x', 1, 'salt-x')
        jwt = JWT.encode({ '_sd' => [d.digest, d.digest] }, key, 'HS256', { typ: 'sd-jwt' })
        expect do
          described_class.new("#{jwt}~#{d.encoded}").verify!(key: key, algorithms: ['HS256'])
        end.to raise_error(JWT::SDJWTDuplicateDigestError)
      end
    end

    context 'unreferenced disclosures' do
      let(:issued) { issue! { |i| i.disclose('name', salt: 's') } }

      it 'rejects an unrelated disclosure appended to the presentation' do
        presentation = JWT::SDJWT.present(issued, 'name')
        unrelated = JWT::SDJWT::Disclosure.property('evil', true, 'salt-evil')
        expect do
          described_class.new("#{presentation.to_s}~#{unrelated.encoded}")
            .verify!(key: key, algorithms: ['HS256'])
        end.to raise_error(JWT::SDJWTUnreferencedDisclosureError, /not referenced/)
      end
    end

    context 'claim overlap' do
      let(:issued) { issue! { |i| i.disclose('name', salt: 's') } }

      it 'rejects a disclosure whose claim overrides an existing plaintext claim' do
        presentation = JWT::SDJWT.present(issued, 'name')
        # Forge the issuer JWT so name is plaintext while the digest still references it.
        payload, header = nil
        segments = issued.jwt.split('.')
        payload = ::JWT::JSON.parse(::JWT::Base64.url_decode(segments[1]))
        payload['name'] = 'Mallory'
        forged_jwt = JWT.encode(payload, key, 'HS256')
        expect do
          described_class.new("#{forged_jwt}~#{presentation.disclosures.first.encoded}")
            .verify!(key: key, algorithms: ['HS256'])
        end.to raise_error(JWT::SDJWTClaimOverlapError, /overrides/)
      end
    end

    context 'invalid nesting' do
      let(:issued) { issue! { |i| i.disclose('name', salt: 's') } }

      def forge(payload)
        JWT.encode(payload, key, 'HS256', { typ: 'sd-jwt' })
      end

      it 'rejects an _sd_alg outside the root object' do
        d = JWT::SDJWT::Disclosure.property('inner', { '_sd_alg' => 'sha-256' }, 'salt-x')
        jwt = forge('iss' => 'x', '_sd' => [d.digest], '_sd_alg' => 'sha-256')
        expect { described_class.new("#{jwt}~#{d.encoded}").verify!(key: key, algorithms: ['HS256']) }
          .to raise_error(JWT::SDJWTInvalidNestingError)
      end

      it 'rejects an ellipsis marker as a bare object key' do
        jwt = forge('a' => { '...' => 'x' }, '_sd_alg' => 'sha-256')
        expect { described_class.new(jwt).verify!(key: key, algorithms: ['HS256']) }
          .to raise_error(JWT::SDJWTInvalidNestingError)
      end

      it 'rejects an array element mixing the ellipsis marker with other keys' do
        jwt = forge('a' => [{ '...' => 'x', 'b' => 1 }], '_sd_alg' => 'sha-256')
        expect { described_class.new(jwt).verify!(key: key, algorithms: ['HS256']) }
          .to raise_error(JWT::SDJWTInvalidNestingError)
      end

      it 'allows an object with _sd nested inside an array element' do
        d = JWT::SDJWT::Disclosure.property('x', 1, 'salt-x')
        jwt = forge('a' => [{ '_sd' => [d.digest] }], '_sd_alg' => 'sha-256')
        result = described_class.new("#{jwt}~#{d.encoded}").verify!(key: key, algorithms: ['HS256'])
        expect(result.claims['a']).to eq([{ 'x' => 1 }])
      end

      it 'rejects a property disclosure referenced by an array placeholder' do
        d = JWT::SDJWT::Disclosure.property('x', 1, 'salt-x')
        jwt = forge('a' => [{ '...' => d.digest }], '_sd_alg' => 'sha-256')
        expect { described_class.new("#{jwt}~#{d.encoded}").verify!(key: key, algorithms: ['HS256']) }
          .to raise_error(JWT::SDJWTInvalidNestingError, /array/)
      end

      it 'rejects an array element disclosure referenced by an object _sd' do
        d = JWT::SDJWT::Disclosure.array_element(1, 'salt-x')
        jwt = forge('_sd' => [d.digest], '_sd_alg' => 'sha-256')
        expect { described_class.new("#{jwt}~#{d.encoded}").verify!(key: key, algorithms: ['HS256']) }
          .to raise_error(JWT::SDJWTInvalidNestingError, /object/)
      end

      it 'rejects a malformed _sd member' do
        jwt = forge('_sd' => 'not-an-array', '_sd_alg' => 'sha-256')
        expect { described_class.new(jwt).verify!(key: key, algorithms: ['HS256']) }
          .to raise_error(JWT::SDJWTMalformedError)
      end

      it 'rejects an unsupported _sd_alg' do
        jwt = forge('_sd_alg' => 'md5')
        expect { described_class.new(jwt).verify!(key: key, algorithms: ['HS256']) }
          .to raise_error(JWT::SDJWTVerificationError, /Unsupported/)
      end
    end

    context 'registered claims' do
      it 'verifies claims against the disclosed result' do
        issued = issue! { |i| i.disclose('name', salt: 's') }
        presentation = JWT::SDJWT.present(issued, 'name')
        result = described_class.new(presentation.to_s).verify!(
          key: key, algorithms: ['HS256'], claims: { iss: 'https://issuer.example' }
        )
        expect(result.claims['iss']).to eq('https://issuer.example')
      end

      it 'fails when an expected claim is not disclosed' do
        issued = issue! { |i| i.disclose('iss', salt: 's'); i.disclose('name', salt: 'n') }
        presentation = JWT::SDJWT.present(issued, 'name')
        expect do
          described_class.new(presentation.to_s).verify!(
            key: key, algorithms: ['HS256'], claims: { iss: 'https://issuer.example' }
          )
        end.to raise_error(JWT::InvalidIssuerError)
      end
    end

    describe '#valid?' do
      let(:issued) { issue! { |i| i.disclose('name', salt: 's') } }

      it 'returns true for a valid presentation' do
        presentation = JWT::SDJWT.present(issued, 'name')
        expect(described_class.new(presentation.to_s).valid?(key: key, algorithms: ['HS256']))
          .to be(true)
      end

      it 'returns false for an invalid presentation' do
        verifier = described_class.new(JWT::SDJWT.present(issued, 'name').to_s)
        expect(verifier.valid?(key: 'wrong-key', algorithms: ['HS256'])).to be(false)
      end
    end
  end
end
