# frozen_string_literal: true

RSpec.describe 'SD-JWT integration' do
  it 'runs the credential example end to end', :slow do
    output = `ruby #{File.join(__dir__, '../../../examples/sd_jwt_credential.rb')} 2>&1`

    expect(output).to include('Presentation 1 (name + age): verification succeeded')
    expect(output).to include('Presentation 2 (address + one nationality): verification succeeded')
    expect(output).to include('Presentation 3 (name + age with an unrelated disclosure): verification failed')
    expect(output).to include('not referenced')
    expect(output).to include('Presentation 4 (name + Key Binding JWT): verification succeeded')
  end

  it 'issues and verifies with RSA keys and a Key Binding JWT' do
    issuer_key = OpenSSL::PKey::RSA.generate(2048)
    holder_key = OpenSSL::PKey::RSA.generate(2048)
    holder_jwk = JWT::JWK.create_from(holder_key).export.reject { |k, _| k == :kid }

    sd_jwt = JWT::SDJWT.issue(
      claims: { 'name' => 'Alice', 'age' => 42 },
      disclosable: %w[name age],
      key: issuer_key,
      algorithm: 'RS256',
      holder_jwk: holder_jwk
    )

    presentation = JWT::SDJWT.present(sd_jwt, %w[name])
    presentation = JWT::SDJWT.bind(presentation, audience: 'verifier', nonce: 'n',
                                                 key: holder_key, algorithm: 'RS256')

    result = JWT::SDJWT.verify(presentation, key: issuer_key.public_key, algorithm: 'RS256',
                                              claims: false, audience: 'verifier', nonce: 'n')

    expect(result.claims).to include('name' => 'Alice')
    expect(result.claims).not_to have_key('age')
  end

  it 'supports HMAC holder Key Binding JWTs' do
    issuer_key = 'issuer-secret'
    holder_key = 'holder-secret'
    holder_jwk = {
      'kty' => 'oct',
      'k' => JWT::Base64.url_encode(holder_key),
      'alg' => 'HS256'
    }

    sd_jwt = JWT::SDJWT.issue(
      claims: { 'name' => 'Alice' },
      disclosable: %w[name],
      key: issuer_key,
      holder_jwk: holder_jwk
    )

    presentation = JWT::SDJWT.present(sd_jwt, %w[name])
    presentation = JWT::SDJWT.bind(presentation, audience: 'v', nonce: 'n',
                                                  key: holder_key, algorithm: 'HS256')

    result = JWT::SDJWT.verify(presentation, key: issuer_key, claims: false,
                                              audience: 'v', nonce: 'n')

    expect(result.key_binding['nonce']).to eq('n')
  end

  it 'supports a dynamic key finder for issuer verification' do
    issuer_key = 'issuer-secret'
    sd_jwt = JWT::SDJWT.issue(claims: { 'name' => 'Alice' }, disclosable: %w[name],
                              key: issuer_key)
    presentation = JWT::SDJWT.present(sd_jwt, %w[name])

    result = JWT::SDJWT::Verifier.new(
      presentation,
      algorithm: 'HS256',
      claims: false,
      key_finder: ->(_token) { issuer_key }
    ).verify

    expect(result.claims['name']).to eq('Alice')
  end

  it 'accepts an array audience containing the expected value' do
    issuer_key = 'issuer-secret'
    holder_key = 'holder-secret'
    holder_jwk = {
      'kty' => 'oct',
      'k' => JWT::Base64.url_encode(holder_key),
      'alg' => 'HS256'
    }

    sd_jwt = JWT::SDJWT.issue(
      claims: { 'name' => 'Alice' },
      disclosable: %w[name],
      key: issuer_key,
      holder_jwk: holder_jwk
    )
    presentation = JWT::SDJWT.present(sd_jwt, %w[name])
    presentation = JWT::SDJWT.bind(presentation, audience: %w[one two], nonce: 'n',
                                                  key: holder_key, algorithm: 'HS256')

    result = JWT::SDJWT.verify(presentation, key: issuer_key, claims: false,
                                              audience: 'two', nonce: 'n')
    expect(result.key_binding['aud']).to eq(%w[one two])
  end

  it 'survives a serialization round trip through strings' do
    issuer_key = OpenSSL::PKey::EC.generate('prime256v1')
    sd_jwt = JWT::SDJWT.issue(
      claims: { 'name' => 'Alice', 'age' => 29 },
      disclosable: %w[name age],
      key: issuer_key,
      algorithm: 'ES256'
    )
    presentation = JWT::SDJWT.present(sd_jwt.to_s, %w[age])

    result = JWT::SDJWT.verify(presentation.to_s, key: issuer_key, algorithm: 'ES256',
                                             claims: false)

    expect(result.claims).to include('age' => 29)
    expect(result.claims).not_to have_key('name')
  end
end
