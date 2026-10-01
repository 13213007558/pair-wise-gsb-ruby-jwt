# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'RFC 9901 SD-JWT integration', type: :integration do
  # Fixed salts make the whole flow reproducible; keys stay local.
  SALTS = {
    name: 'fixed-salt-name',
    age: 'fixed-salt-age',
    country: 'fixed-salt-country',
    locality: 'fixed-salt-locality',
    us: 'fixed-salt-us',
    de: 'fixed-salt-de'
  }.freeze

  let(:issuer_key) { OpenSSL::PKey::EC.generate('prime256v1') }
  let(:holder_key) { OpenSSL::PKey::EC.generate('prime256v1') }

  let(:claims) do
    {
      'iss' => 'https://issuer.example',
      'cnf' => { 'jwk' => JWT::JWK.create_from(holder_key).export },
      'name' => 'Alice',
      'age' => 42,
      'address' => { 'country' => 'US', 'locality' => 'Springfield' },
      'nationalities' => %w[US DE]
    }
  end

  let(:issued) do
    JWT::SDJWT.issue(claims, key: issuer_key, algorithm: 'ES256') do |issuer|
      issuer.disclose('name', salt: SALTS[:name])
      issuer.disclose('age', salt: SALTS[:age])
      issuer.disclose('address', 'country', salt: SALTS[:country])
      issuer.disclose('address', 'locality', salt: SALTS[:locality])
      issuer.disclose('nationalities', 0, salt: SALTS[:us])
      issuer.disclose('nationalities', 1, salt: SALTS[:de])
    end
  end

  it 'supports two distinct disclosure sets for the same issued credential' do
    presentation_a = JWT::SDJWT.present(
      issued, 'name', ['address', 'country'], ['nationalities', 0]
    )
    presentation_b = JWT::SDJWT.present(
      issued, 'age',
      ['address', 'country'], ['address', 'locality'],
      ['nationalities', 0], ['nationalities', 1]
    )

    result_a = JWT::SDJWT.verify(presentation_a.to_s, key: issuer_key, algorithms: ['ES256'])
    result_b = JWT::SDJWT.verify(presentation_b.to_s, key: issuer_key, algorithms: ['ES256'])

    expect(result_a.claims).to include(
      'name' => 'Alice',
      'address' => { 'country' => 'US' },
      'nationalities' => ['US']
    )
    expect(result_a.claims).not_to include('age')
    expect(result_a.claims['address']).not_to include('locality')

    expect(result_b.claims).to include(
      'age' => 42,
      'address' => { 'country' => 'US', 'locality' => 'Springfield' },
      'nationalities' => %w[US DE]
    )
    expect(result_b.claims).not_to include('name')
  end

  it 'rejects a presentation carrying an unrelated disclosure' do
    presentation = JWT::SDJWT.present(issued, 'name')
    unrelated = JWT::SDJWT::Disclosure.property('is_admin', true, 'fixed-salt-unrelated')
    tampered = "#{presentation.to_s}~#{unrelated.encoded}"

    expect do
      JWT::SDJWT.verify(tampered, key: issuer_key, algorithms: ['ES256'])
    end.to raise_error(JWT::SDJWTUnreferencedDisclosureError)
  end

  it 'supports a verified Key Binding JWT on one of the presentations' do
    presentation = JWT::SDJWT.present(issued, 'name')
    JWT::SDJWT.bind_key(
      presentation,
      key: holder_key,
      algorithm: 'ES256',
      audience: 'verifier.example',
      nonce: 'verifier-nonce'
    )

    result = JWT::SDJWT.verify(
      presentation.to_s,
      key: issuer_key,
      algorithms: ['ES256'],
      expected_audience: 'verifier.example',
      expected_nonce: 'verifier-nonce'
    )
    expect(result.key_binding['nonce']).to eq('verifier-nonce')
    expect(result.key_binding['sd_hash']).to eq(JWT::SDJWT.sd_hash(
      JWT::SDJWT::Presentation.parse(presentation.to_s.sub(/~[^~]*\z/, ''))
    ))
  end
end
