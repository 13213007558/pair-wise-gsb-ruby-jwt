# frozen_string_literal: true

RSpec.describe JWT::JWK::KeyFinder do
  let(:rsa_keypair) { OpenSSL::PKey::RSA.generate(2048) }
  let(:rsa_jwk) { JWT::JWK.new(rsa_keypair, 'shared-kid') }
  let(:hmac_jwk) { JWT::JWK.new('secret', 'shared-kid') }
  let(:payload) { { 'data' => 'something' } }

  def token_for(algorithm, key, headers)
    JWT::EncodedToken.new(JWT.encode(payload, key, algorithm, headers))
  end

  describe '#call' do
    context 'without a key filter' do
      it 'keeps the legacy first-match behaviour' do
        token = token_for('RS256', rsa_keypair, kid: 'shared-kid')
        finder = described_class.new(jwks: { keys: [rsa_jwk.export, hmac_jwk.export(include_private: true)] })
        expect(finder.call(token).to_der).to eq(rsa_keypair.public_key.to_der)
      end
    end

    context 'with a key filter' do
      let(:filter) { JWT::JWK::KeyFilter.new }

      context 'when a RSA and a HMAC key share the same kid' do
        let(:jwks) { { keys: [hmac_jwk.export(include_private: true), rsa_jwk.export] } }

        it 'selects the RSA key for a RS256 token' do
          token = token_for('RS256', rsa_keypair, kid: 'shared-kid')
          finder = described_class.new(jwks: jwks, key_filter: filter)
          expect(finder.call(token).to_der).to eq(rsa_keypair.public_key.to_der)
        end

        it 'selects the HMAC key for a HS256 token' do
          token = token_for('HS256', 'secret', kid: 'shared-kid')
          finder = described_class.new(jwks: jwks, key_filter: filter)
          expect(finder.call(token)).to eq('secret')
        end

        it 'is not affected by the order of the keys in the jwks' do
          token = token_for('RS256', rsa_keypair, kid: 'shared-kid')
          reversed = { keys: jwks[:keys].reverse }
          finder = described_class.new(jwks: reversed, key_filter: filter)
          expect(finder.call(token).to_der).to eq(rsa_keypair.public_key.to_der)
        end
      end

      context 'when the jwks contains an encryption key with the same kid' do
        let(:encryption_jwk) { JWT::JWK.new(rsa_jwk.export.merge(use: 'enc', alg: 'RSA-OAEP')) }
        let(:signing_jwk) { JWT::JWK.new(rsa_jwk.export.merge(use: 'sig', alg: 'RS256')) }

        it 'selects the signing key regardless of the key order' do
          token = token_for('RS256', rsa_keypair, kid: 'shared-kid')
          [encryption_jwk, signing_jwk].permutation.each do |keys|
            finder = described_class.new(jwks: { keys: keys.map(&:export) }, key_filter: filter)
            expect(finder.call(token).to_der).to eq(rsa_keypair.public_key.to_der)
          end
        end
      end

      context 'when no key survives the filtering' do
        it 'raises SignatureError' do
          token = token_for('RS256', rsa_keypair, kid: 'shared-kid')
          finder = described_class.new(jwks: { keys: [hmac_jwk.export(include_private: true)] }, key_filter: filter)
          expect { finder.call(token) }.to raise_error(JWT::SignatureError, 'Could not find public key for kid shared-kid')
        end
      end

      context 'when multiple keys survive the filtering' do
        let(:other_rsa_jwk) { JWT::JWK.new(OpenSSL::PKey::RSA.generate(2048), 'shared-kid') }

        it 'raises JWKError instead of silently picking the first key' do
          token = token_for('RS256', rsa_keypair, kid: 'shared-kid')
          [rsa_jwk, other_rsa_jwk].permutation.each do |keys|
            finder = described_class.new(jwks: { keys: keys.map(&:export) }, key_filter: filter)
            expect { finder.call(token) }.to raise_error(JWT::JWKError, 'Multiple keys found in jwks for kid shared-kid')
          end
        end
      end

      context 'when the filter is given as a Hash' do
        it 'builds a KeyFilter from the hash' do
          token = token_for('RS256', rsa_keypair, kid: 'shared-kid')
          jwks = { keys: [hmac_jwk.export(include_private: true), rsa_jwk.export] }
          finder = described_class.new(jwks: jwks, key_filter: { use: 'sig' })
          expect(finder.call(token).to_der).to eq(rsa_keypair.public_key.to_der)
        end
      end

      context 'when the filter is a callable' do
        it 'uses the callable to select keys' do
          token = token_for('RS256', rsa_keypair, kid: 'shared-kid')
          jwks = { keys: [hmac_jwk.export(include_private: true), rsa_jwk.export] }
          finder = described_class.new(jwks: jwks, key_filter: ->(key, _header) { key[:kty] == 'RSA' })
          expect(finder.call(token).to_der).to eq(rsa_keypair.public_key.to_der)
        end
      end

      context 'with a thumbprint whitelist' do
        let(:thumbprint) { JWT::JWK::Thumbprint.new(rsa_jwk).generate }
        let(:other_rsa_jwk) { JWT::JWK.new(OpenSSL::PKey::RSA.generate(2048), 'shared-kid') }

        it 'selects only the whitelisted key' do
          token = token_for('RS256', rsa_keypair, kid: 'shared-kid')
          jwks = { keys: [other_rsa_jwk.export, rsa_jwk.export] }
          finder = described_class.new(jwks: jwks, key_filter: JWT::JWK::KeyFilter.new(thumbprints: [thumbprint]))
          expect(finder.call(token).to_der).to eq(rsa_keypair.public_key.to_der)
        end

        it 'fails when the matching key is not whitelisted' do
          token = token_for('RS256', rsa_keypair, kid: 'shared-kid')
          jwks = { keys: [rsa_jwk.export] }
          finder = described_class.new(jwks: jwks, key_filter: JWT::JWK::KeyFilter.new(thumbprints: ['unknown-thumbprint']))
          expect { finder.call(token) }.to raise_error(JWT::SignatureError, 'Could not find public key for kid shared-kid')
        end
      end
    end
  end
end
