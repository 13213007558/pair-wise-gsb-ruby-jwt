# frozen_string_literal: true

RSpec.describe JWT::SDJWT::Presenter do
  let(:issuer_key) { 'issuer-secret' }
  let(:holder_key) { OpenSSL::PKey::EC.generate('prime256v1') }
  let(:holder_jwk) { JWT::JWK.create_from(holder_key).export }

  let(:claims) do
    {
      'name' => 'Alice',
      'age' => 29,
      'address' => { 'street' => 'Main St', 'locality' => 'Berlin' },
      'nationalities' => %w[CN DE]
    }
  end

  let(:salts) { %w[s1 s2 s3 s4 s5 s6] }
  let(:salt_counter) { [0] }
  let(:salt_provider) { -> { salts[salt_counter[0]].tap { salt_counter[0] += 1 } } }

  let(:sd_jwt) do
    JWT::SDJWT::Issuer.new(
      claims: claims,
      key: issuer_key,
      algorithm: 'HS256',
      disclosable: %w[name age address.street address.locality nationalities[0] nationalities[1]],
      holder_jwk: holder_jwk,
      salt_provider: salt_provider
    ).issue
  end

  describe '#present' do
    it 'selects only the disclosures for the given paths' do
      presentation = described_class.new(sd_jwt).present(%w[name age])

      expect(presentation.disclosures.map(&:claim_name)).to eq(%w[name age])
      expect(presentation.kb_jwt).to be_nil
    end

    it 'selects nested object member disclosures' do
      presentation = described_class.new(sd_jwt).present(['address.street'])

      expect(presentation.disclosures.map(&:to_a)).to eq([['s3', 'street', 'Main St']])
    end

    it 'selects array element disclosures' do
      presentation = described_class.new(sd_jwt).present(['nationalities[1]'])

      expect(presentation.disclosures.map(&:to_a)).to eq([['s6', 'DE']])
    end

    it 'does not mutate the original SD-JWT' do
      original = sd_jwt.disclosures.length
      described_class.new(sd_jwt).present(%w[name])

      expect(sd_jwt.disclosures.length).to eq(original)
    end

    it 'raises when no disclosure exists for a path' do
      expect { described_class.new(sd_jwt).present(['age', 'address.country']) }
        .to raise_error(JWT::SDJWTFormatError, /address\.country/)
    end

    it 'works on a serialized SD-JWT' do
      presentation = JWT::SDJWT.present(sd_jwt.to_s, %w[name])
      expect(presentation.disclosures.map(&:claim_name)).to eq(['name'])
    end
  end

  describe '#bind' do
    let(:presentation) { described_class.new(sd_jwt).present(%w[name]) }

    it 'adds a Key Binding JWT signed with the holder key' do
      bound = described_class.new(sd_jwt).bind(
        presentation,
        audience: 'verifier', nonce: 'n1', key: holder_key
      )

      expect(bound.kb_jwt).to be_a(String)
      expect(bound.kb_jwt.count('.')).to eq(2)
    end

    it 'infers ES256 from an EC key' do
      bound = described_class.new(sd_jwt).bind(
        presentation, audience: 'verifier', nonce: 'n1', key: holder_key
      )
      kb_token = JWT::EncodedToken.new(bound.kb_jwt)

      expect(kb_token.header['alg']).to eq('ES256')
      expect(kb_token.header['typ']).to eq('kb+jwt')
    end

    it 'raises when the issuer JWT carries no cnf.jwk' do
      plain = JWT::SDJWT::Issuer.new(claims: claims, key: issuer_key,
                                     disclosable: %w[name]).issue
      p = described_class.new(plain).present(%w[name])

      expect do
        described_class.new(plain).bind(p, audience: 'v', nonce: 'n', key: holder_key)
      end.to raise_error(JWT::SDJWTFormatError, /cnf\.jwk/)
    end
  end
end

RSpec.describe JWT::SDJWT::Presenter, 'algorithm inference' do
  let(:claims) { { 'name' => 'A' } }

  def issue_with(holder_jwk)
    JWT::SDJWT::Issuer.new(
      claims: claims, key: 'issuer', disclosable: %w[name], holder_jwk: holder_jwk
    ).issue
  end

  it 'infers RS256 for RSA keys' do
    rsa = OpenSSL::PKey::RSA.generate(2048)
    holder_jwk = JWT::JWK.create_from(rsa).export.reject { |k, _| k == :kid }
    sd_jwt = issue_with(holder_jwk)
    bound = described_class.new(sd_jwt).bind(
      JWT::SDJWT.present(sd_jwt, %w[name]), audience: 'v', nonce: 'n', key: rsa
    )

    expect(JWT::EncodedToken.new(bound.kb_jwt).header['alg']).to eq('RS256')
  end

  it 'infers HS256 for string keys' do
    secret = 'holder-secret'
    holder_jwk = { 'kty' => 'oct', 'k' => JWT::Base64.url_encode(secret), 'alg' => 'HS256' }
    sd_jwt = issue_with(holder_jwk)
    bound = described_class.new(sd_jwt).bind(
      JWT::SDJWT.present(sd_jwt, %w[name]), audience: 'v', nonce: 'n', key: secret
    )

    expect(JWT::EncodedToken.new(bound.kb_jwt).header['alg']).to eq('HS256')
  end

  it 'raises when the algorithm cannot be inferred' do
    holder_jwk = JWT::JWK.create_from(OpenSSL::PKey::EC.generate('prime256v1')).export
    sd_jwt = issue_with(holder_jwk)

    expect do
      described_class.new(sd_jwt).bind(
        JWT::SDJWT.present(sd_jwt, %w[name]), audience: 'v', nonce: 'n', key: Object.new
      )
    end.to raise_error(JWT::SDJWTFormatError, /infer/)
  end
end
