# frozen_string_literal: true

RSpec.describe JWT::SDJWT::Verifier do
  let(:issuer_key) { OpenSSL::PKey::EC.generate('prime256v1') }
  let(:issuer_public_key) { issuer_key.public_key }
  let(:holder_key) { OpenSSL::PKey::EC.generate('prime256v1') }
  let(:holder_jwk) { JWT::JWK.create_from(holder_key).export.reject { |k, _| k == :kid } }

  let(:claims) do
    {
      'iss' => 'https://issuer.example',
      'name' => 'Alice Chen',
      'age' => 29,
      'address' => {
        'street' => '12 Maple Street',
        'locality' => 'Berlin',
        'country' => 'DE'
      },
      'nationalities' => %w[CN DE]
    }
  end

  let(:salts) { ('a'..'z').map { |c| "salt-#{c}" } }
  let(:salt_counter) { [0] }
  let(:salt_provider) { -> { salts[salt_counter[0]].tap { salt_counter[0] += 1 } } }

  let(:disclosable) do
    %w[name age address.street address.locality address.country nationalities[0] nationalities[1]]
  end

  let(:sd_jwt) do
    JWT::SDJWT::Issuer.new(
      claims: claims,
      key: issuer_key,
      algorithm: 'ES256',
      disclosable: disclosable,
      holder_jwk: holder_jwk,
      salt_provider: salt_provider
    ).issue
  end

  def verify(presentation, **options)
    defaults = { key: issuer_public_key, algorithm: 'ES256', claims: false }
    described_class.new(presentation, **defaults.merge(options)).verify
  end

  def re_sign_issuer(payload, key: issuer_key, header: { 'typ' => 'sd-jwt' })
    JWT::Token.new(payload: payload, header: header).tap do |token|
      token.sign!(algorithm: 'ES256', key: key)
    end.jwt
  end

  describe '#verify happy paths' do
    it 'returns only the disclosed top level claims' do
      presentation = JWT::SDJWT.present(sd_jwt, %w[name age])
      result = verify(presentation)

      expect(result.claims).to include('name' => 'Alice Chen', 'age' => 29)
      expect(result.claims).not_to include('address' => include('street' => anything))
    end

    it 'keeps always visible claims (iss) and drops undisclosed contents' do
      presentation = JWT::SDJWT.present(sd_jwt, %w[name])
      result = verify(presentation)

      expect(result.claims['iss']).to eq('https://issuer.example')
      expect(result.claims['address']).to eq({})
      expect(result.claims['nationalities']).to eq([])
    end

    it 'returns disclosed nested object members' do
      presentation = JWT::SDJWT.present(sd_jwt, %w[address.street address.country])
      result = verify(presentation)

      expect(result.claims['address']).to eq('street' => '12 Maple Street', 'country' => 'DE')
    end

    it 'returns disclosed array elements at the correct positions' do
      presentation = JWT::SDJWT.present(sd_jwt, %w[nationalities[1]])
      result = verify(presentation)

      expect(result.claims['nationalities']).to eq(['DE'])
    end

    it 'removes all array elements when none are disclosed' do
      presentation = JWT::SDJWT.present(sd_jwt, %w[age])
      result = verify(presentation)

      expect(result.claims['nationalities']).to eq([])
    end

    it 'returns the issuer header and the used disclosures' do
      presentation = JWT::SDJWT.present(sd_jwt, %w[name])
      result = verify(presentation)

      expect(result.header['alg']).to eq('ES256')
      expect(result.disclosures.map(&:claim_name)).to eq(['name'])
    end

    it 'accepts a serialized SD-JWT string' do
      presentation = JWT::SDJWT.present(sd_jwt, %w[name])
      result = JWT::SDJWT.verify(presentation.to_s, key: issuer_public_key,
                                                          algorithm: 'ES256', claims: false)

      expect(result.claims['name']).to eq('Alice Chen')
    end

    it 'supports HMAC keys' do
      hmac = 'secret-key'
      issued = JWT::SDJWT::Issuer.new(claims: { 'name' => 'A' }, key: hmac,
                                      disclosable: %w[name]).issue
      presentation = JWT::SDJWT.present(issued, %w[name])
      result = JWT::SDJWT.verify(presentation, key: hmac, algorithm: 'HS256', claims: false)

      expect(result.claims['name']).to eq('A')
    end

    it 'supports JWT::JWK verification keys' do
      presentation = JWT::SDJWT.present(sd_jwt, %w[name])
      jwk = JWT::JWK::EC.new(issuer_key)
      result = described_class.new(presentation, key: jwk, algorithm: 'ES256',
                                                    claims: false).verify

      expect(result.claims['name']).to eq('Alice Chen')
    end
  end

  describe '#verify signature and standard claims' do
    it 'rejects a presentation signed with a different key' do
      other_key = OpenSSL::PKey::EC.generate('prime256v1')
      presentation = JWT::SDJWT.present(sd_jwt, %w[name])

      expect { verify(presentation, key: other_key) }
        .to raise_error(JWT::VerificationError)
    end

    it 'rejects the wrong algorithm' do
      presentation = JWT::SDJWT.present(sd_jwt, %w[name])

      expect { verify(presentation, algorithm: 'RS256') }
        .to raise_error(JWT::Error)
    end

    it 'verifies standard claims when given' do
      past = Time.now.to_i - 100
      issued = JWT::SDJWT::Issuer.new(
        claims: { 'name' => 'A', 'exp' => past },
        key: issuer_key, algorithm: 'ES256', disclosable: %w[name]
      ).issue
      presentation = JWT::SDJWT.present(issued, %w[name])

      expect do
        described_class.new(presentation, key: issuer_public_key, algorithm: 'ES256',
                                           claims: [:exp]).verify
      end.to raise_error(JWT::ExpiredSignature)
    end
  end

  describe '#verify rejections' do
    it 'rejects a disclosure that is not referenced' do
      presentation = JWT::SDJWT.present(sd_jwt, %w[name])
      stranger = JWT::SDJWT::Disclosure.new(salt: 'x', claim_name: 'admin', value: true)
      tampered = JWT::SDJWT::CompoundSdJwt.new(
        issuer_jwt: presentation.issuer_jwt,
        disclosures: presentation.disclosures + [stranger]
      )

      expect { verify(tampered) }
        .to raise_error(JWT::SDJWTVerificationError, /not referenced/)
    end

    it 'rejects duplicated disclosures' do
      presentation = JWT::SDJWT.present(sd_jwt, %w[name])
      tampered = JWT::SDJWT::CompoundSdJwt.new(
        issuer_jwt: presentation.issuer_jwt,
        disclosures: presentation.disclosures + presentation.disclosures
      )

      expect { verify(tampered) }
        .to raise_error(JWT::SDJWTVerificationError, /duplicate/)
    end

    it 'rejects a disclosure whose digest does not match the content' do
      presentation = JWT::SDJWT.present(sd_jwt, %w[name])
      forged = JWT::SDJWT::Disclosure.new(salt: presentation.disclosures.first.salt,
                                          claim_name: 'name', value: 'Mallory')
      tampered = JWT::SDJWT::CompoundSdJwt.new(
        issuer_jwt: presentation.issuer_jwt,
        disclosures: [forged]
      )

      expect { verify(tampered) }
        .to raise_error(JWT::SDJWTVerificationError, /not referenced/)
    end

    it 'rejects a disclosure that would overwrite a plain claim' do
      disclosure = JWT::SDJWT::Disclosure.new(salt: 's', claim_name: 'iss', value: 'evil')
      payload = {
        'iss' => 'real',
        '_sd' => [disclosure.digest],
        '_sd_alg' => 'sha-256'
      }
      jwt = re_sign_issuer(payload)
      sd = JWT::SDJWT::CompoundSdJwt.new(issuer_jwt: jwt, disclosures: [disclosure])

      expect { verify(sd) }.to raise_error(JWT::SDJWTVerificationError, /overwrites/)
    end

    it 'rejects an _sd member nested inside an array' do
      payload = { 'list' => [{ '_sd' => [] }], '_sd_alg' => 'sha-256' }
      jwt = re_sign_issuer(payload)
      sd = JWT::SDJWT::CompoundSdJwt.new(issuer_jwt: jwt)

      expect { verify(sd) }.to raise_error(JWT::SDJWTVerificationError, /Illegal "_sd"/)
    end

    it 'rejects an _sd_alg member nested below the root' do
      payload = { 'x' => { '_sd_alg' => 'sha-256' } }
      jwt = re_sign_issuer(payload)
      sd = JWT::SDJWT::CompoundSdJwt.new(issuer_jwt: jwt)

      expect { verify(sd) }.to raise_error(JWT::SDJWTVerificationError, /Illegal nested "_sd_alg"/)
    end

    it 'rejects an "..." marker inside an object' do
      disclosure = JWT::SDJWT::Disclosure.new(salt: 's', value: 1)
      payload = { 'x' => { '...' => disclosure.digest } }
      jwt = re_sign_issuer(payload)
      sd = JWT::SDJWT::CompoundSdJwt.new(issuer_jwt: jwt, disclosures: [disclosure])

      expect { verify(sd) }.to raise_error(JWT::SDJWTVerificationError, /Illegal "\.\.\."/)
    end

    it 'rejects an array marker that contains additional members' do
      disclosure = JWT::SDJWT::Disclosure.new(salt: 's', value: 1)
      payload = { 'list' => [{ '...' => disclosure.digest, 'extra' => 2 }] }
      jwt = re_sign_issuer(payload)
      sd = JWT::SDJWT::CompoundSdJwt.new(issuer_jwt: jwt, disclosures: [disclosure])

      expect { verify(sd) }.to raise_error(JWT::SDJWTVerificationError, /only contain/)
    end

    it 'rejects an object member disclosure referenced from an array' do
      disclosure = JWT::SDJWT::Disclosure.new(salt: 's', claim_name: 'k', value: 1)
      payload = { 'list' => [{ '...' => disclosure.digest }] }
      jwt = re_sign_issuer(payload)
      sd = JWT::SDJWT::CompoundSdJwt.new(issuer_jwt: jwt, disclosures: [disclosure])

      expect { verify(sd) }.to raise_error(JWT::SDJWTVerificationError, /Object member disclosure/)
    end

    it 'rejects an array element disclosure referenced from an object' do
      disclosure = JWT::SDJWT::Disclosure.new(salt: 's', value: 1)
      payload = { '_sd' => [disclosure.digest], '_sd_alg' => 'sha-256' }
      jwt = re_sign_issuer(payload)
      sd = JWT::SDJWT::CompoundSdJwt.new(issuer_jwt: jwt, disclosures: [disclosure])

      expect { verify(sd) }.to raise_error(JWT::SDJWTVerificationError, /Array element disclosure/)
    end

    it 'rejects the same digest appearing twice in the issuer claims' do
      disclosure = JWT::SDJWT::Disclosure.new(salt: 's', claim_name: 'k', value: 1)
      payload = {
        '_sd' => [disclosure.digest, disclosure.digest],
        '_sd_alg' => 'sha-256'
      }
      jwt = re_sign_issuer(payload)
      sd = JWT::SDJWT::CompoundSdJwt.new(issuer_jwt: jwt, disclosures: [disclosure])

      expect { verify(sd) }.to raise_error(JWT::SDJWTVerificationError, /Duplicate disclosure digest/)
    end

    it 'accepts a disclosure whose value itself contains undisclosed digests' do
      nested_d = JWT::SDJWT::Disclosure.new(salt: 'sn', claim_name: 'city', value: 'Berlin')
      outer_d = JWT::SDJWT::Disclosure.new(
        salt: 'so', claim_name: 'address',
        value: { '_sd' => [nested_d.digest] }
      )
      payload = { '_sd' => [outer_d.digest], '_sd_alg' => 'sha-256' }
      jwt = re_sign_issuer(payload)
      outer_only = JWT::SDJWT::CompoundSdJwt.new(issuer_jwt: jwt, disclosures: [outer_d])

      # The nested digest without a disclosure stays hidden instead of looping.
      expect(verify(outer_only).claims['address']).to eq({})
    end

    it 'rejects an unsupported _sd_alg' do
      jwt = re_sign_issuer({ '_sd_alg' => 'sha-1' })
      sd = JWT::SDJWT::CompoundSdJwt.new(issuer_jwt: jwt)

      expect { verify(sd) }.to raise_error(JWT::SDJWTVerificationError, /Unsupported _sd_alg/)
    end

    it 'rejects a non object issuer payload' do
      jwt = JWT::Token.new(payload: [1, 2]).tap { |t| t.sign!(algorithm: 'ES256', key: issuer_key) }.jwt
      sd = JWT::SDJWT::CompoundSdJwt.new(issuer_jwt: jwt)

      expect { verify(sd) }.to raise_error(JWT::SDJWTVerificationError, /JSON object/)
    end

    it 'rejects an unexpected typ header' do
      jwt = re_sign_issuer({}, header: { 'typ' => 'jwt' })
      sd = JWT::SDJWT::CompoundSdJwt.new(issuer_jwt: jwt)

      expect { verify(sd) }.to raise_error(JWT::SDJWTVerificationError, /typ/)
    end

    it 'accepts an application profile typ like vc+sd-jwt' do
      jwt = re_sign_issuer({ 'name' => 'A' }, header: { 'typ' => 'vc+sd-jwt' })
      sd = JWT::SDJWT::CompoundSdJwt.new(issuer_jwt: jwt)

      expect(verify(sd).claims).to include('name' => 'A')
    end

    it 'rejects malformed disclosures' do
      presentation = JWT::SDJWT.present(sd_jwt, %w[name])
      bad = JWT::Base64.url_encode(JSON.generate(['only-salt']))

      expect do
        described_class.new("#{presentation.issuer_jwt}~#{bad}~",
                            key: issuer_public_key, algorithm: 'ES256', claims: false).verify
      end.to raise_error(JWT::SDJWTFormatError, /two or three elements/)
    end

    it 'rejects malformed SD-JWT serializations' do
      expect { described_class.new('not-an-sd-jwt', key: issuer_key).verify }
        .to raise_error(JWT::SDJWTFormatError)
    end
  end

  describe 'nested disclosures' do
    let(:disclosable) { ['address'] }

    it 'releases the whole nested object with one disclosure' do
      presentation = JWT::SDJWT.present(sd_jwt, ['address'])
      result = verify(presentation)

      expect(result.claims['address']).to eq(claims['address'])
    end

    it 'supports disclosures nested inside disclosed values' do
      nested_d = JWT::SDJWT::Disclosure.new(
        salt: 'nested-salt', claim_name: 'city', value: 'Berlin'
      )
      address_d = JWT::SDJWT::Disclosure.new(
        salt: 'addr-salt', claim_name: 'address',
        value: { '_sd' => [nested_d.digest] }
      )
      payload = {
        '_sd' => [address_d.digest],
        '_sd_alg' => 'sha-256'
      }
      jwt = re_sign_issuer(payload)

      outer = JWT::SDJWT::CompoundSdJwt.new(issuer_jwt: jwt, disclosures: [address_d])
      expect(verify(outer).claims['address']).to eq({})

      inner = JWT::SDJWT::CompoundSdJwt.new(issuer_jwt: jwt, disclosures: [address_d, nested_d])
      expect(verify(inner).claims['address']).to eq('city' => 'Berlin')
    end
  end

  describe 'Key Binding JWT' do
    def bind(presentation, audience: 'verifier.example', nonce: 'nonce-1', key: holder_key, **options)
      JWT::SDJWT::Presenter.new(sd_jwt).bind(
        presentation, audience: audience, nonce: nonce, key: key, **options
      )
    end

    it 'verifies a valid Key Binding JWT and returns its payload' do
      presentation = bind(JWT::SDJWT.present(sd_jwt, %w[name]))
      result = verify(presentation, audience: 'verifier.example', nonce: 'nonce-1')

      expect(result.key_binding).to match(
        'iat' => an_instance_of(Integer),
        'aud' => 'verifier.example',
        'nonce' => 'nonce-1',
        'sd_hash' => an_instance_of(String)
      )
    end

    it 'rejects a Key Binding JWT signed by another key' do
      other = OpenSSL::PKey::EC.generate('prime256v1')
      presentation = bind(JWT::SDJWT.present(sd_jwt, %w[name]), key: other)

      expect do
        verify(presentation, audience: 'verifier.example', nonce: 'nonce-1')
      end.to raise_error(JWT::VerificationError)
    end

    it 'rejects a wrong audience' do
      presentation = bind(JWT::SDJWT.present(sd_jwt, %w[name]), audience: 'other')

      expect do
        verify(presentation, audience: 'verifier.example', nonce: 'nonce-1')
      end.to raise_error(JWT::SDJWTVerificationError, /audience/)
    end

    it 'rejects a wrong nonce' do
      presentation = bind(JWT::SDJWT.present(sd_jwt, %w[name]))

      expect do
        verify(presentation, audience: 'verifier.example', nonce: 'wrong')
      end.to raise_error(JWT::SDJWTVerificationError, /nonce/)
    end

    it 'rejects a tampered sd_hash' do
      presentation = bind(JWT::SDJWT.present(sd_jwt, %w[name]))
      # Add another disclosure without updating the Key Binding JWT.
      presentation.disclosures << JWT::SDJWT.present(sd_jwt, %w[age]).disclosures.first

      expect do
        verify(presentation, audience: 'verifier.example', nonce: 'nonce-1')
      end.to raise_error(JWT::SDJWTVerificationError, /sd_hash/)
    end

    it 'requires the Key Binding JWT when audience or nonce is expected' do
      presentation = JWT::SDJWT.present(sd_jwt, %w[name])

      expect { verify(presentation, audience: 'verifier.example') }
        .to raise_error(JWT::SDJWTVerificationError, /Key Binding JWT is required/)
    end

    it 'rejects a Key Binding JWT with typ kb+jwt but alg none' do
      presentation = JWT::SDJWT.present(sd_jwt, %w[name])
      kb_header = JWT::Base64.url_encode(JSON.generate('alg' => 'none', 'typ' => 'kb+jwt'))
      kb_payload = JWT::Base64.url_encode(JSON.generate(
        'iat' => Time.now.to_i, 'aud' => 'verifier.example', 'nonce' => 'nonce-1', 'sd_hash' => 'x'
      ))
      presentation.kb_jwt = "#{kb_header}.#{kb_payload}."

      expect do
        verify(presentation, audience: 'verifier.example', nonce: 'nonce-1')
      end.to raise_error(JWT::SDJWTVerificationError, /signature algorithm/)
    end

    it 'rejects a Key Binding JWT with a wrong typ' do
      presentation = JWT::SDJWT.present(sd_jwt, %w[name])
      bound = bind(presentation)
      kb_token = JWT::EncodedToken.new(bound.kb_jwt)
      bad_header = kb_token.header.merge('typ' => 'jwt')
      bad_kb = JWT::Token.new(payload: kb_token.unverified_payload, header: bad_header)
      bad_kb.sign!(algorithm: 'ES256', key: holder_key)
      presentation.kb_jwt = bad_kb.jwt

      expect do
        verify(presentation, audience: 'verifier.example', nonce: 'nonce-1')
      end.to raise_error(JWT::SDJWTVerificationError, /kb\+jwt/)
    end
  end
end

RSpec.describe JWT::SDJWT::Verifier, 'defensive validations' do
  let(:issuer_key) { 'secret' }

  def sign(payload, key: issuer_key, header: {})
    JWT::Token.new(payload: payload, header: header).tap do |t|
      t.sign!(algorithm: 'HS256', key: key)
    end.jwt
  end

  def verify_sd(jwt, disclosures: [])
    sd = JWT::SDJWT::CompoundSdJwt.new(issuer_jwt: jwt, disclosures: disclosures)
    JWT::SDJWT.verify(sd, key: issuer_key, claims: false)
  end

  it 'rejects an _sd member that is not an array' do
    expect { verify_sd(sign({ '_sd' => 'nope' })) }
      .to raise_error(JWT::SDJWTVerificationError, /must be an array/)
  end

  it 'rejects non string digests in _sd' do
    expect { verify_sd(sign({ '_sd' => [123] })) }
      .to raise_error(JWT::SDJWTVerificationError, /digests must be strings/)
  end

  it 'rejects a non string digest in an array marker' do
    expect { verify_sd(sign({ "list" => [{ "..." => 5 }] })) }
      .to raise_error(JWT::SDJWTVerificationError, /digest must be a string/)
  end

  it 'rejects a Key Binding JWT without a cnf.jwk holder key' do
    presentation = JWT::SDJWT.issue(
      claims: { 'name' => 'A' }, disclosable: %w[name], key: issuer_key
    )
    bound = JWT::SDJWT::CompoundSdJwt.new(issuer_jwt: presentation.issuer_jwt,
                                          disclosures: presentation.disclosures)
    kb = JWT::Token.new(
      payload: { 'iat' => Time.now.to_i, 'aud' => 'v', 'nonce' => 'n', 'sd_hash' => 'x' },
      header: { 'alg' => 'HS256', 'typ' => 'kb+jwt' }
    ).tap { |t| t.sign!(algorithm: 'HS256', key: 'kb') }.jwt
    bound.kb_jwt = kb

    expect do
      JWT::SDJWT.verify(bound, key: issuer_key, claims: false, audience: 'v', nonce: 'n')
    end.to raise_error(JWT::SDJWTVerificationError, /cnf\.jwk/)
  end

  it 'rejects a non object Key Binding JWT payload' do
    holder = OpenSSL::PKey::EC.generate('prime256v1')
    holder_jwk = JWT::JWK.create_from(holder).export.reject { |k, _| k == :kid }
    sd = JWT::SDJWT.issue(claims: { 'name' => 'A' }, disclosable: %w[name],
                          key: issuer_key, holder_jwk: holder_jwk)
    bound = JWT::SDJWT.present(sd, %w[name])
    kb = JWT::Token.new(payload: [1, 2], header: { 'typ' => 'kb+jwt' })
                 .tap { |t| t.sign!(algorithm: 'ES256', key: holder) }.jwt
    bound.kb_jwt = kb

    expect do
      JWT::SDJWT.verify(bound, key: issuer_key, claims: false, audience: 'v', nonce: 'n')
    end.to raise_error(JWT::SDJWTVerificationError, /payload must be a JSON object/)
  end

  it 'requires aud and nonce claims in a presented Key Binding JWT' do
    holder = OpenSSL::PKey::EC.generate('prime256v1')
    holder_jwk = JWT::JWK.create_from(holder).export.reject { |k, _| k == :kid }
    sd = JWT::SDJWT.issue(claims: { 'name' => 'A' }, disclosable: %w[name],
                          key: issuer_key, holder_jwk: holder_jwk)
    bound = JWT::SDJWT.present(sd, %w[name])
    prefix = JWT::SDJWT::CompoundSdJwt.new(issuer_jwt: bound.issuer_jwt,
                                           disclosures: bound.disclosures).to_s
    sd_hash = JWT::SDJWT::Digestable.new.digest(prefix)
    kb = JWT::Token.new(payload: { 'iat' => Time.now.to_i, 'sd_hash' => sd_hash },
                        header: { 'typ' => 'kb+jwt' })
                 .tap { |t| t.sign!(algorithm: 'ES256', key: holder) }.jwt
    bound.kb_jwt = kb

    expect do
      JWT::SDJWT.verify(bound, key: issuer_key, claims: false)
    end.to raise_error(JWT::SDJWTVerificationError, /missing "aud"/)
  end

  it 'raises without any key or key finder' do
    sd = JWT::SDJWT.issue(claims: { 'a' => 1 }, key: issuer_key)
    expect do
      described_class.new(sd, algorithm: 'HS256', claims: false).verify
    end.to raise_error(JWT::VerificationError, /No verification key/)
  end
end
