# frozen_string_literal: true

RSpec.describe JWT::SDJWT do
  let(:issuer_key) { OpenSSL::PKey::EC.generate('prime256v1') }
  let(:holder_key) { OpenSSL::PKey::EC.generate('prime256v1') }
  let(:holder_jwk) { JWT::JWK.create_from(holder_key).export.reject { |k, _| k == :kid } }

  let(:claims) do
    {
      'name' => 'Alice',
      'age' => 29,
      'address' => { 'street' => 'Main St', 'city' => 'Berlin' },
      'nationalities' => %w[CN DE]
    }
  end

  let(:salts) { ('1'..'9').to_a }
  let(:salt_counter) { [0] }
  let(:salt_provider) { -> { salts[salt_counter[0]].tap { salt_counter[0] += 1 } } }

  let(:sd_jwt) do
    described_class.issue(
      claims: claims,
      key: issuer_key,
      algorithm: 'ES256',
      disclosable: %w[name age address.street address.city nationalities[0] nationalities[1]],
      holder_jwk: holder_jwk,
      salt_provider: salt_provider
    )
  end

  it 'issues, presents and verifies an object member disclosure' do
    presentation = described_class.present(sd_jwt, %w[name])
    result = described_class.verify(presentation, key: issuer_key, algorithm: 'ES256', claims: false)

    expect(result.claims['name']).to eq('Alice')
    expect(result.claims).not_to have_key('age')
  end

  it 'issues, presents and verifies a nested disclosure' do
    presentation = described_class.present(sd_jwt, ['address.city'])
    result = described_class.verify(presentation, key: issuer_key, algorithm: 'ES256', claims: false)

    expect(result.claims['address']).to eq('city' => 'Berlin')
  end

  it 'issues, presents and verifies an array element disclosure' do
    presentation = described_class.present(sd_jwt, ['nationalities[0]'])
    result = described_class.verify(presentation, key: issuer_key, algorithm: 'ES256', claims: false)

    expect(result.claims['nationalities']).to eq(['CN'])
  end

  it 'verifies a presentation with a Key Binding JWT' do
    presentation = described_class.present(sd_jwt, %w[name])
    presentation = described_class.bind(presentation, audience: 'verifier',
                                                      nonce: 'nonce', key: holder_key)

    result = described_class.verify(presentation, key: issuer_key, algorithm: 'ES256',
                                                 claims: false, audience: 'verifier', nonce: 'nonce')

    expect(result.claims['name']).to eq('Alice')
    expect(result.key_binding['nonce']).to eq('nonce')
  end

  it 'rejects a presentation containing an unrelated disclosure' do
    stranger = JWT::SDJWT::Disclosure.new(salt: 'x', claim_name: 'admin', value: true)
    presentation = described_class.present(sd_jwt, %w[name])
    tampered = JWT::SDJWT::CompoundSdJwt.new(
      issuer_jwt: presentation.issuer_jwt,
      disclosures: presentation.disclosures + [stranger]
    )

    expect do
      described_class.verify(tampered, key: issuer_key, algorithm: 'ES256', claims: false)
    end.to raise_error(JWT::SDJWTVerificationError, /not referenced/)
  end

  it 'does not implement any credential network protocol (plain strings only)' do
    expect(sd_jwt).to be_a(JWT::SDJWT::CompoundSdJwt)
    expect(sd_jwt.to_s).to be_a(String)
  end
end
