# frozen_string_literal: true

RSpec.describe JWT::SDJWT do
  let(:issuer_key) { test_pkey('rsa-2048-private.pem') }
  let(:issuer_public_key) { test_pkey('rsa-2048-public.pem') }
  let(:holder_key) { test_pkey('ec256-private.pem') }

  let(:payload) do
    {
      'iss' => 'https://issuer.example',
      'sub' => 'subject-1',
      'given_name' => 'John',
      'email' => nil,
      'address' => {
        'country' => 'US',
        'region' => 'NY',
        'location' => { 'lat' => 40.7, 'lng' => -74.0 }
      },
      'scores' => [1, 2, 3]
    }
  end

  let(:issued) do
    described_class.issue(
      payload: payload,
      signer_key: issuer_key,
      algorithm: 'RS256',
      disclosable_paths: [
        %w[given_name],
        %w[address region],
        %w[address location],
        %w[scores 1]
      ],
      decoys: 2,
      holder_jwk: holder_key
    )
  end

  let(:all_disclosures) { issued.disclosures.map(&:encoded) }

  def digest_for(encoded)
    JWT::SDJWT::HashAlgorithm.find('sha-256').digest(encoded)
  end

  def count_digests(value)
    case value
    when Hash
      children = value.reject { |key, _| key == '_sd' }.values
      value.fetch('_sd', []).size + children.inject(0) { |total, child| total + count_digests(child) }
    when Array then value.inject(0) { |total, child| total + (child.is_a?(Hash) && child.key?('') ? 1 : count_digests(child)) }
    else 0
    end
  end

  def decoy_count(value)
    case value
    when Hash
      sd = value.fetch('_sd', [])
      real = sd.count { |digest| all_digests.include?(digest) }
      other = value.reject { |key, _| key == '_sd' }.values.inject(0) { |total, child| total + decoy_count(child) }
      sd.size - real + other
      when Array
        value.inject(0) do |total, child|
          next total + 1 if child.is_a?(Hash) && child.key?('') && !all_digests.include?(child[''])

          total + decoy_count(child)
        end
    else 0
    end
  end

  def all_digests
    @all_digests ||= all_disclosures.map { |encoded| digest_for(encoded) }
  end

  describe '#issue' do
    it 'creates nested object and array digests with decoy digests' do
      pairs = issued.disclosures.map { |d| [d.key, d.value] }
      expect(pairs).to include(['given_name', 'John'], ['region', 'NY'])
      location = pairs.assoc('location').last
      expect(location['lat']).to eq(40.7)
      expect(location['lng']).to eq(-74.0)
      expect(location['_sd']).to be_an(Array)
      array_disclosure = issued.disclosures.find(&:array_element?)
      expect(array_disclosure.value).to eq(2)

      expect(issued.claims['address']['region']).to be_nil
      expect(issued.claims['address'].key?('region')).to eq(false)
      expect(issued.claims['scores'][1].keys).to eq([''])
      expect(issued.claims['scores'][1]['']).to be_a(String)
      expect(issued.claims['cnf']['jwk'].keys).to match_array(%w[kty crv x y])

      digest_count = count_digests(issued.claims)
      expect(digest_count).to eq(all_disclosures.size + decoy_count(issued.claims))
      expect(issued.claims['address']['_sd'].size).to be >= 3
      expect(issued.claims['scores'].count { |v| v.is_a?(Hash) && v[''] }).to eq(3)
    end

    it 'keeps a pre-existing cnf subtree plaintext and outside decoy processing' do
      cnf = { 'jwk' => { 'custom' => 'plaintext' }, 'x5t#S256' => 'thumbprint' }
      token = described_class.issue(
        payload: payload.merge('cnf' => cnf),
        signer_key: issuer_key,
        algorithm: 'RS256',
        disclosable_paths: [%w[address region]],
        decoys: 2
      )

      expect(token.claims['cnf']).to eq(cnf)
      expect(count_digests(token.claims['cnf'])).to eq(0)
    end

    it 'rejects reserved SD-JWT claim names in issuer payloads' do
      expect do
        described_class.issue(
          payload: { '_sd_alg' => 'sha-256' },
          signer_key: issuer_key,
          algorithm: 'RS256'
        )
      end.to raise_error(JWT::SDJWT::Error, /reserved/)
    end

    it 'rejects invalid issuer salt and decoy parameters' do
      expect { described_class.issue(payload: payload, signer_key: issuer_key, salt_bytes: 8) }
        .to raise_error(JWT::SDJWT::Error, /salt_bytes/)
      expect { described_class.issue(payload: payload, signer_key: issuer_key, decoys: -1) }
        .to raise_error(JWT::SDJWT::Error, /negative/)
    end

    it 'hashes the original base64url disclosure encoding without reordering JSON' do
      encoded = 'WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ'
      disclosure = JWT::SDJWT::Disclosure.new(encoded)
      digest = OpenSSL::Digest::SHA256.digest(encoded)

      expect(disclosure.key).to eq('given_name')
      expect(disclosure.value).to eq('John')
      expect(disclosure.digest(JWT::SDJWT::HashAlgorithm.find('sha-256')))
        .to eq(Base64.urlsafe_encode64(digest, padding: false))
    end

    it 'verifies the RFC 9901 appendix disclosures using their original encodings' do
      given_name = 'WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ'
      family_name = 'WyI2R2VMdXZtcEN6YmtSeW9RIiwiZmFtaWx5X25hbWUiLCJEb2UiXQ'
      email = 'WyJlbHVWNU9nM2dTTklJOEVZbnM4ZG9iIiwiZW1haWwiLCJqb2huZG9lQGV4YW1wbGUuY29tIl0'
      digests = [given_name, family_name, email].map { |disclosure| digest_for(disclosure) }
      issuer_payload = {
        'sub' => 'user_42',
        '_sd' => digests.shuffle,
        '_sd_alg' => 'sha-256'
      }
      jwt = JWT.encode(issuer_payload, issuer_key, 'RS256')
      presentation = [jwt, given_name, family_name, ''].join('~')
      result = described_class.verify(presentation, issuer_public_key, algorithm: 'RS256')

      expect(result.claims['sub']).to eq('user_42')
      expect(result.claims['given_name']).to eq('John')
      expect(result.claims['family_name']).to eq('Doe')
      expect(result.claims.key?('email')).to eq(false)
    end
  end

  describe '#present and #verify' do
    def present(paths, key_binding: nil)
      described_class.present(
        issued.sd_jwt,
        paths: paths,
        key_binding: key_binding
      )
    end

    it 'reveals selected nested and array claims while leaving others unknowable' do
      token = present([%w[address region], %w[scores 1]])
      result = described_class.verify(token, issuer_public_key, algorithm: 'RS256')

      expect(result.claims['address']).to eq('country' => 'US', 'region' => 'NY')
      expect(result.claims['address'].key?('location')).to eq(false)
      expect(result.claims['address'].key?('lat')).to eq(false)
      expect(result.claims['scores'].first(3)).to eq([1, 2, 3])
      result.claims['scores'].last(2).each do |marker|
        expect(marker['']).to be_a(String)
        expect(marker['']).to match(/\A[A-Za-z0-9_-]+\z/)
      end
      expect(result.claims.key?('given_name')).to eq(false)
      expect(result.claims.key?('email')).to eq(true)
      expect(result.claims['email']).to be_nil
      expect(result.disclosures.size).to eq(2)
    end

    it 'selects a disclosed object and all of its recursively disclosed descendants' do
      token = present([%w[address location]])
      result = described_class.verify(token, issuer_public_key, algorithm: 'RS256')

      expect(result.claims['address']['location']).to eq('lat' => 40.7, 'lng' => -74.0)
      expect(result.claims.key?('given_name')).to eq(false)
    end

    it 'treats an explicitly empty path list as no disclosures' do
      token = described_class.present(issued.sd_jwt, paths: [])
      result = described_class.verify(token, issuer_public_key, algorithm: 'RS256')

      expect(token).to end_with('~')
      expect(result.disclosures).to be_empty
      expect(result.claims.key?('given_name')).to eq(false)
      expect(result.claims['address'].key?('region')).to eq(false)
    end

    it 'verifies key binding audience, nonce, sd_hash, and caller supplied time' do
      time = Time.at(1_700_000_000)
      token = present(
        [%w[address region]],
        key_binding: {
          holder_key: holder_key,
          audience: 'https://verifier.example',
          nonce: 'nonce-123',
          now: time,
          algorithm: 'ES256'
        }
      )

      result = described_class.verify(
        token,
        issuer_public_key,
        algorithm: 'RS256',
        key_binding: {
          audience: 'https://verifier.example',
          nonce: 'nonce-123',
          now: time
        }
      )

      expect(result.key_binding.payload['aud']).to eq('https://verifier.example')
      expect(result.key_binding.payload['nonce']).to eq('nonce-123')
      expect(result.key_binding.payload['iat']).to eq(time.to_i)
    end

    it 'rejects key binding with a different audience, nonce, time, or sd_hash' do
      time = Time.at(1_700_000_000)
      token = present(
        [%w[address region]],
        key_binding: {
          holder_key: holder_key,
          audience: 'https://verifier.example',
          nonce: 'nonce-123',
          now: time,
          algorithm: 'ES256'
        }
      )

      aggregate_failures do
        expect { verify_kb(token, audience: 'wrong', nonce: 'nonce-123', now: time) }
          .to raise_error(JWT::SDJWT::KeyBindingError, /audience/)
        expect { verify_kb(token, audience: 'https://verifier.example', nonce: 'wrong', now: time) }
          .to raise_error(JWT::SDJWT::KeyBindingError, /nonce/)
        expect { verify_kb(token, audience: 'https://verifier.example', nonce: 'nonce-123', now: time + 10) }
          .to raise_error(JWT::SDJWT::KeyBindingError, /iat/)
      end
    end

    it 'rejects a key binding over an altered presentation' do
      time = Time.at(1_700_000_000)
      token = present(
        [%w[address region]],
        key_binding: {
          holder_key: holder_key,
          audience: 'https://verifier.example',
          nonce: 'nonce-123',
          now: time,
          algorithm: 'ES256'
        }
      )
      segments = token.split('~')
      disclosure = JSON.parse(Base64.urlsafe_decode64(segments[1]))
      disclosure[2] = 'MA'
      segments[1] = Base64.urlsafe_encode64(JSON.generate(disclosure), padding: false)
      altered = segments[0..-2].join('~') + '~' + segments.last

      expect do
        described_class.verify(
          altered,
          issuer_public_key,
          algorithm: 'RS256',
          key_binding: { audience: 'https://verifier.example', nonce: 'nonce-123', now: time }
        )
      end.to raise_error(JWT::SDJWT::DisclosureVerificationError)
    end

    it 'rejects duplicate disclosures' do
      encoded = all_disclosures.first
      token = signed_token([encoded, encoded])

      expect { described_class.verify(token, issuer_public_key, algorithm: 'RS256') }
        .to raise_error(JWT::SDJWT::DisclosureVerificationError, /Duplicate disclosure/)
    end

    it 'rejects a presentation containing an unexpected key binding' do
      time = Time.at(1_700_000_000)
      token = present(
        [%w[address region]],
        key_binding: {
          holder_key: holder_key,
          audience: 'https://verifier.example',
          nonce: 'nonce-123',
          now: time,
          algorithm: 'ES256'
        }
      )

      expect { described_class.verify(token, issuer_public_key, algorithm: 'RS256') }
        .to raise_error(JWT::SDJWT::KeyBindingError, /not expected/)
    end

    it 'rejects unreferenced disclosures' do
      salt = JWT::SDJWT::Disclosure.salt(SecureRandom, 16)
      unreferenced = JWT::SDJWT::Disclosure.create('extra', 'value', salt: salt).encoded
      token = signed_token([all_disclosures.first, unreferenced])

      expect { described_class.verify(token, issuer_public_key, algorithm: 'RS256') }
        .to raise_error(JWT::SDJWT::DisclosureVerificationError, /not referenced/)
    end

    it 'rejects a disclosure that conflicts with an existing plaintext claim' do
      digest = digest_for(DisclosureEncoding.given_name)
      conflicting_payload = {
        'given_name' => 'Jane',
        '_sd' => [digest],
        '_sd_alg' => 'sha-256'
      }
      jwt = JWT.encode(conflicting_payload, issuer_key, 'RS256')
      token = [jwt, DisclosureEncoding.given_name, ''].join('~')

      expect { described_class.verify(token, issuer_public_key, algorithm: 'RS256') }
        .to raise_error(JWT::SDJWT::DisclosureVerificationError, /conflicts/)
    end

    it 'rejects an object disclosure used as an array element' do
      token = replace_first_array_marker(issued.sd_jwt, digest_for(DisclosureEncoding.given_name))
      token = signed_token_from(token, [DisclosureEncoding.given_name])

      expect { described_class.verify(token, issuer_public_key, algorithm: 'RS256') }
        .to raise_error(JWT::SDJWT::MalformedTokenError, /cannot be used as an array/)
    end

    it 'rejects a padded disclosure and an object claim using the array marker name' do
      short_salt = Base64.urlsafe_encode64(JSON.generate(['short', 'short_claim', 'x']), padding: false)
      padded = DisclosureEncoding.given_name + '='
      jwt = JWT.encode({ '_sd_alg' => 'sha-256' }, issuer_key, 'RS256')
      expect { described_class.verify([jwt, padded, ''].join('~'), issuer_public_key, algorithm: 'RS256') }
        .to raise_error(JWT::SDJWT::MalformedDisclosureError, /base64url/)
      expect { described_class.verify([jwt, short_salt, ''].join('~'), issuer_public_key, algorithm: 'RS256') }
        .to raise_error(JWT::SDJWT::MalformedDisclosureError, /128 bits/)

      bad_payload = { '' => 'x', '_sd_alg' => 'sha-256' }
      bad_jwt = JWT.encode(bad_payload, issuer_key, 'RS256')
      expect { described_class.verify(bad_jwt, issuer_public_key, algorithm: 'RS256') }
        .to raise_error(JWT::SDJWT::MalformedTokenError, /reserved|marker/)
    end

    def verify_kb(token, audience:, nonce:, now:)
      described_class.verify(
        token,
        issuer_public_key,
        algorithm: 'RS256',
        key_binding: { audience: audience, nonce: nonce, now: now }
      )
    end

    def signed_token(encoded_disclosures)
      [issued.jwt, *encoded_disclosures, ''].join('~')
    end

    def signed_token_from(original_token, disclosures)
      issuer_jwt = original_token.split('~').first
      [issuer_jwt, *disclosures, ''].join('~')
    end

    def replace_first_array_marker(token, digest)
      jwt = token.split('~').first
      payload = JSON.parse(Base64.urlsafe_decode64(jwt.split('.')[1]))
      replace(payload, digest)
      JWT.encode(payload, issuer_key, 'RS256')
    end

    def replace(value, digest)
      case value
      when Hash
        if value['scores'].is_a?(Array)
          value['scores'][1] = { '' => digest }
        else
          value.each_value { |child| replace(child, digest) }
        end
      when Array
        value.each { |child| replace(child, digest) }
      end
    end

  end

  module DisclosureEncoding
    module_function

    def given_name
      'WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ'
    end
  end
end
