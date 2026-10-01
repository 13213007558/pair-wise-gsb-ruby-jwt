# frozen_string_literal: true

RSpec.describe JWT::SDJWT::Issuer do
  let(:issuer_key) { 'issuer-secret' }
  let(:claims) do
    {
      'name' => 'Alice',
      'age' => 29,
      'address' => { 'street' => 'Main St', 'locality' => 'Berlin' },
      'nationalities' => %w[CN DE]
    }
  end
  let(:disclosable) { %w[name age address.street nationalities[0]] }

  let(:salts) { %w[s1 s2 s3 s4] }
  let(:salt_counter) { [0] }
  let(:salt_provider) { -> { salts[salt_counter[0]].tap { salt_counter[0] += 1 } } }

  def issue(**overrides)
    described_class.new(
      claims: claims,
      key: issuer_key,
      algorithm: 'HS256',
      disclosable: disclosable,
      salt_provider: salt_provider,
      **overrides
    ).issue
  end

  describe '#issue' do
    it 'replaces object members with digests and keeps plain claims' do
      sd_jwt = issue

      payload = sd_jwt.unverified_payload
      expect(payload).not_to have_key('name')
      expect(payload).not_to have_key('age')
      expect(payload['_sd']).to eq(sd_jwt.disclosures[0..1].map { |d| d.digest })
      expect(payload['age']).to be_nil
      expect(payload['address']).not_to have_key('street')
      expect(payload['address']['locality']).to eq('Berlin')
    end

    it 'replaces array elements with "..." digest markers' do
      sd_jwt = issue
      payload = sd_jwt.unverified_payload

      expect(payload['nationalities']).to match(
        [{ '...' => an_instance_of(String) }, 'DE']
      )
    end

    it 'sets the _sd_alg claim' do
      expect(issue.unverified_payload['_sd_alg']).to eq('sha-256')
    end

    it 'produces three element disclosures for object members' do
      sd_jwt = issue
      name_disc = sd_jwt.disclosures.find { |d| d.claim_name == 'name' }

      expect(name_disc.to_a).to eq(['s1', 'name', 'Alice'])
    end

    it 'produces two element disclosures for array elements' do
      sd_jwt = issue
      array_disc = sd_jwt.disclosures.find { |d| d.claim_name.nil? }

      expect(array_disc.to_a).to eq(['s4', 'CN'])
    end

    it 'signs the issuer JWT with the standard JWT interfaces' do
      sd_jwt = issue
      header, = JWT.decode(sd_jwt.issuer_jwt, issuer_key, true, algorithm: 'HS256')

      expect(header).to include('_sd_alg' => 'sha-256')
    end

    it 'defaults the typ header to sd-jwt' do
      token = JWT::EncodedToken.new(issue.issuer_jwt)
      expect(token.header['typ']).to eq('sd-jwt')
    end

    it 'allows additional and overriding headers' do
      sd_jwt = issue(headers: { 'cty' => 'example', 'typ' => 'custom+sd-jwt' })
      token = JWT::EncodedToken.new(sd_jwt.issuer_jwt)

      expect(token.header['cty']).to eq('example')
      expect(token.header['typ']).to eq('custom+sd-jwt')
    end

    it 'works with EC keys and ES256' do
      ec_key = OpenSSL::PKey::EC.generate('prime256v1')
      sd_jwt = issue(key: ec_key, algorithm: 'ES256')

      expect do
        JWT::EncodedToken.new(sd_jwt.issuer_jwt).verify_signature!(algorithm: 'ES256', key: ec_key)
      end.not_to raise_error
    end

    it 'works with a JWT::JWK signing key' do
      ec_key = OpenSSL::PKey::EC.generate('prime256v1')
      jwk = JWT::JWK.create_from(ec_key)
      sd_jwt = issue(key: jwk, algorithm: 'ES256')

      expect do
        JWT::EncodedToken.new(sd_jwt.issuer_jwt).verify_signature!(algorithm: 'ES256', key: ec_key)
      end.not_to raise_error
    end

    it 'embeds the holder public key as cnf.jwk' do
      holder_key = OpenSSL::PKey::EC.generate('prime256v1')
      holder_jwk = JWT::JWK.create_from(holder_key).export
      sd_jwt = issue(holder_jwk: holder_jwk)

      cnf = sd_jwt.unverified_payload['cnf']
      expect(cnf['jwk']).to include('kty' => 'EC', 'crv' => 'P-256')
      expect(cnf['jwk']).not_to have_key('d')
    end

    it 'accepts a plain Hash as holder jwk' do
      holder_key = OpenSSL::PKey::EC.generate('prime256v1')
      holder_jwk = JWT::JWK.create_from(holder_key).export.transform_keys(&:to_s)
      sd_jwt = issue(holder_jwk: holder_jwk)

      expect(sd_jwt.unverified_payload.dig('cnf', 'jwk', 'kty')).to eq('EC')
    end

    it 'uses random salts by default' do
      disclosable_one = ['name']
      claims_one = { 'name' => 'Alice' }

      first = described_class.new(claims: claims_one, key: issuer_key, disclosable: disclosable_one).issue
      second = described_class.new(claims: claims_one, key: issuer_key, disclosable: disclosable_one).issue

      expect(first.disclosures.first.salt).not_to eq(second.disclosures.first.salt)
    end

    it 'supports deeply nested object members' do
      deep = { 'a' => { 'b' => { 'c' => 1 } } }
      sd_jwt = described_class.new(claims: deep, key: issuer_key, disclosable: ['a.b.c'],
                                   salt_provider: salt_provider).issue

      payload = sd_jwt.unverified_payload
      expect(payload.dig('a', 'b')).to have_key('_sd')
      expect(sd_jwt.disclosures.first.to_a).to eq(['s1', 'c', 1])
    end

    it 'supports nested array indexes' do
      deep = { 'a' => { 'list' => [10, 20] } }
      sd_jwt = described_class.new(claims: deep, key: issuer_key, disclosable: ['a.list[1]'],
                                   salt_provider: salt_provider).issue

      expect(sd_jwt.unverified_payload.dig('a', 'list')).to match([10, { '...' => an_instance_of(String) }])
      expect(sd_jwt.disclosures.first.value).to eq(20)
    end

    it 'raises when the claims are not a Hash' do
      expect { issue(claims: 'not-a-hash') }.to raise_error(JWT::SDJWTInvalidPayload)
    end

    it 'raises when a disclosable path does not exist' do
      expect { issue(disclosable: ['name', 'unknown']) }
        .to raise_error(JWT::SDJWTInvalidPayload, /unknown/)
    end

    it 'raises when a nested path does not exist' do
      expect { issue(disclosable: ['address.nope']) }
        .to raise_error(JWT::SDJWTInvalidPayload, /address\.nope/)
    end

    it 'raises on an invalid array index' do
      expect { issue(disclosable: ['nationalities[5]']) }
        .to raise_error(JWT::SDJWTInvalidPayload, /nationalities\[5\]/)
    end

    it 'raises when an ancestor is already disclosable' do
      expect { issue(disclosable: ['address', 'address.street']) }
        .to raise_error(JWT::SDJWTInvalidPayload, /nested inside disclosable path/)
    end

    it 'raises on reserved claim names in the payload' do
      expect { issue(claims: { '_sd' => [] }) }
        .to raise_error(JWT::SDJWTInvalidPayload, /reserved/)
    end

    it 'raises on reserved claim names nested in the payload' do
      expect { issue(claims: { 'x' => { '...' => 1 } }) }
        .to raise_error(JWT::SDJWTInvalidPayload, /reserved/)
    end

    it 'raises on reserved path components' do
      expect { issue(disclosable: ['_sd']) }
        .to raise_error(JWT::SDJWTInvalidPayload, /reserved/)
    end

    it 'raises on malformed paths' do
      expect { issue(disclosable: ['a..b']) }
        .to raise_error(JWT::SDJWTInvalidPayload)
      expect { issue(disclosable: ['a[x]']) }
        .to raise_error(JWT::SDJWTInvalidPayload)
    end

    it 'does not set _sd_alg when nothing is disclosable' do
      payload = described_class.new(claims: { 'a' => 1 }, key: issuer_key,
                                    disclosable: []).issue.unverified_payload
      expect(payload).not_to have_key('_sd_alg')
    end
  end
end

RSpec.describe JWT::SDJWT::Issuer, 'additional validations' do
  let(:issuer_key) { 'secret' }
  let(:base_claims) { { 'name' => 'A', 'cnf' => { 'jwk' => {} } } }

  def issue(**overrides)
    options = { claims: base_claims, key: issuer_key, disclosable: [] }.merge(overrides)
    described_class.new(**options).issue
  end

  it 'rejects claims already carrying a cnf member when holder_jwk is given' do
    expect { issue(holder_jwk: { 'kty' => 'oct' }) }
      .to raise_error(JWT::SDJWTInvalidPayload, /cnf/)
  end

  it 'rejects duplicate disclosable paths' do
    expect do
      issue(claims: { 'a' => 1 }, disclosable: %w[a a])
    end.to raise_error(JWT::SDJWTInvalidPayload, /unique/)
  end
end

RSpec.describe JWT::SDJWT::Issuer, 'symbol keys' do
  it 'accepts symbol keyed claims and normalizes them' do
    sd_jwt = described_class.new(
      claims: { name: 'Alice', address: { city: 'Berlin' } },
      key: 'secret',
      disclosable: ['name', 'address.city']
    ).issue

    presentation = JWT::SDJWT.present(sd_jwt, %w[name address.city])
    result = JWT::SDJWT.verify(presentation, key: 'secret', claims: false)

    expect(result.claims).to eq('address' => { 'city' => 'Berlin' }, 'name' => 'Alice')
  end
end

RSpec.describe JWT::SDJWT::Issuer, 'salt and reserved name edge cases' do
  it 'raises when the salt provider does not return a string' do
    expect do
      described_class.new(claims: { 'a' => 1 }, key: 'k', disclosable: %w[a],
                          salt_provider: -> { 123 }).issue
    end.to raise_error(JWT::SDJWTInvalidPayload, /Salt provider/)
  end

  it 'raises when an array element uses the reserved "..." key' do
    expect do
      described_class.new(claims: { 'list' => [{ '...' => 'x' }] }, key: 'k',
                          disclosable: []).issue
    end.to raise_error(JWT::SDJWTInvalidPayload, /reserved/)
  end

  it 'raises on empty path strings' do
    expect do
      described_class.new(claims: { 'a' => 1 }, key: 'k', disclosable: ['']).issue
    end.to raise_error(JWT::SDJWTInvalidPayload)
  end

  it 'normalizes JWK keys for the cnf claim' do
    holder = OpenSSL::PKey::EC.generate('prime256v1')
    jwk = JWT::JWK.create_from(holder)
    sd_jwt = described_class.new(
      claims: { 'a' => 1 }, key: 'k', disclosable: [], holder_jwk: jwk
    ).issue

    expect(sd_jwt.unverified_payload.dig('cnf', 'jwk', 'kty')).to eq('EC')
  end
end
