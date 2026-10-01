# frozen_string_literal: true

require 'spec_helper'

RSpec.describe JWT::SDJWT::KeyBinding do
  let(:issuer_key) { OpenSSL::PKey::EC.generate('prime256v1') }
  let(:holder_key) { OpenSSL::PKey::EC.generate('prime256v1') }
  let(:holder_jwk) { JWT::JWK.create_from(holder_key).export }
  let(:audience) { 'https://verifier.example' }
  let(:nonce) { 'verifier-nonce' }

  let(:issued) do
    claims = {
      'iss' => 'https://issuer.example',
      'name' => 'Alice',
      'cnf' => { 'jwk' => holder_jwk }
    }
    JWT::SDJWT::Issuer.new(claims).tap { |i| i.disclose('name', salt: 'salt-name') }
                               .issue!(key: issuer_key, algorithm: 'ES256')
  end

  def bound_presentation(overrides = {})
    presentation = JWT::SDJWT.present(issued, 'name')
    options = {
      presentation: presentation,
      key: holder_key,
      algorithm: 'ES256',
      audience: audience,
      nonce: nonce
    }.merge(overrides)
    kb = described_class.sign(**options)
    presentation.key_binding_jwt = kb
    presentation
  end

  def verify(presentation, overrides = {})
    options = {
      key: issuer_key,
      algorithms: ['ES256'],
      expected_audience: audience,
      expected_nonce: nonce
    }.merge(overrides)
    JWT::SDJWT::Verifier.new(presentation.to_s).verify!(**options)
  end

  describe '.sign / verification' do
    it 'creates a verifiable Key Binding JWT' do
      presentation = bound_presentation
      result = verify(presentation)
      expect(result.key_binding['nonce']).to eq(nonce)
      expect(result.key_binding['aud']).to eq(audience)
      expect(result.key_binding['sd_hash']).to eq(JWT::SDJWT.sd_hash(presentation))
      expect(result.key_binding['iat']).to be_a(Integer)
    end

    it 'sets the kb+jwt typ header' do
      presentation = bound_presentation
      header = ::JWT::JSON.parse(::JWT::Base64.url_decode(presentation.key_binding_jwt.split('.').first))
      expect(header['typ']).to eq('kb+jwt')
      expect(header['alg']).to eq('ES256')
    end

    it 'binds the key identified by cnf.jwk' do
      presentation = bound_presentation
      # Signing with a different holder key must fail verification.
      presentation.key_binding_jwt = described_class.sign(
        presentation: presentation,
        key: OpenSSL::PKey::EC.generate('prime256v1'),
        algorithm: 'ES256', audience: audience, nonce: nonce
      )
      expect { verify(presentation) }.to raise_error(JWT::SDJWTKeyBindingError, /signature/)
    end
  end

  describe 'claim checks' do
    it 'rejects a wrong audience' do
      expect { verify(bound_presentation, expected_audience: 'someone-else') }
        .to raise_error(JWT::SDJWTKeyBindingError, /aud/)
    end

    it 'accepts one of multiple audiences' do
      presentation = bound_presentation(audience: %w[a b])
      expect(verify(presentation, expected_audience: 'b').key_binding['aud']).to eq(%w[a b])
    end

    it 'rejects a wrong nonce' do
      expect { verify(bound_presentation, expected_nonce: 'tampered') }
        .to raise_error(JWT::SDJWTKeyBindingError, /nonce/)
    end

    it 'rejects an sd_hash that does not match the presentation' do
      presentation = bound_presentation
      # Sign a KB-JWT that is valid for a presentation without disclosures and
      # attach it to a presentation that does carry a disclosure: the signature
      # is valid but sd_hash differs.
      empty_presentation = JWT::SDJWT::Presentation.new(presentation.jwt)
      kb = described_class.sign(presentation: empty_presentation, key: holder_key,
                                algorithm: 'ES256', audience: audience, nonce: nonce)
      presentation.key_binding_jwt = kb
      expect { verify(presentation) }.to raise_error(JWT::SDJWTKeyBindingError, /sd_hash/)
    end

    it 'requires cnf.jwk in the issuer payload' do
      claims = { 'name' => 'Alice' }
      issued_no_cnf = JWT::SDJWT::Issuer.new(claims).tap { |i| i.disclose('name', salt: 's') }
                                                .issue!(key: issuer_key, algorithm: 'ES256')
      presentation = JWT::SDJWT.present(issued_no_cnf, 'name')
      kb = described_class.sign(presentation: presentation, key: holder_key, algorithm: 'ES256',
                                audience: audience, nonce: nonce)
      presentation.key_binding_jwt = kb
      expect do
        JWT::SDJWT::Verifier.new(presentation.to_s).verify!(
          key: issuer_key, algorithms: ['ES256'],
          expected_audience: audience, expected_nonce: nonce
        )
      end.to raise_error(JWT::SDJWTKeyBindingError, /cnf.jwk/)
    end

    it "rejects the 'none' algorithm" do
      presentation = bound_presentation
      token = JWT::Token.new(
        payload: {
          iat: Time.now.to_i, aud: audience, nonce: nonce,
          sd_hash: JWT::SDJWT.sd_hash(presentation)
        },
        header: { typ: 'kb+jwt' }
      )
      token.sign!(algorithm: 'none', key: nil)
      presentation.key_binding_jwt = token.jwt
      expect { verify(presentation) }.to raise_error(JWT::SDJWTKeyBindingError)
    end

    it 'rejects a wrong typ header' do
      presentation = bound_presentation
      kb = JWT.encode(
        { iat: Time.now.to_i, aud: audience, nonce: nonce, sd_hash: JWT::SDJWT.sd_hash(presentation) },
        holder_key, 'ES256', { typ: 'jwt' }
      )
      presentation.key_binding_jwt = kb
      expect { verify(presentation) }.to raise_error(JWT::SDJWTKeyBindingError, /typ/)
    end

    it 'requires audience and nonce expectations when a KB-JWT is present' do
      presentation = bound_presentation
      expect do
        JWT::SDJWT::Verifier.new(presentation.to_s).verify!(
          key: issuer_key, algorithms: ['ES256']
        )
      end.to raise_error(JWT::SDJWTKeyBindingError, /audience/)
    end
  end

  describe 'without a Key Binding JWT' do
    it 'does not require audience/nonce options' do
      presentation = JWT::SDJWT.present(issued, 'name')
      result = JWT::SDJWT::Verifier.new(presentation.to_s).verify!(
        key: issuer_key, algorithms: ['ES256']
      )
      expect(result.key_binding).to be_nil
    end
  end
end
