# frozen_string_literal: true

RSpec.describe JWT::JWK::KeyFilter do
  let(:rsa_jwk) { JWT::JWK.new(OpenSSL::PKey::RSA.generate(2048), 'rsa-key') }
  let(:hmac_jwk) { JWT::JWK.new('secret', 'hmac-key') }

  describe '.kty_for_algorithm' do
    it 'maps HMAC algorithms to oct' do
      expect(described_class.kty_for_algorithm('HS256')).to eq('oct')
    end

    it 'maps RSA algorithms to RSA' do
      expect(described_class.kty_for_algorithm('RS256')).to eq('RSA')
      expect(described_class.kty_for_algorithm('PS512')).to eq('RSA')
    end

    it 'maps ECDSA algorithms to EC' do
      expect(described_class.kty_for_algorithm('ES256')).to eq('EC')
    end

    it 'maps EdDSA to OKP' do
      expect(described_class.kty_for_algorithm('EdDSA')).to eq('OKP')
    end

    it 'returns nil for unknown algorithms' do
      expect(described_class.kty_for_algorithm('none')).to be_nil
      expect(described_class.kty_for_algorithm(nil)).to be_nil
    end
  end

  describe '#match?' do
    subject(:filter) { described_class.new }

    it 'accepts a key without any metadata' do
      expect(filter.match?(rsa_jwk, algorithm: 'RS256')).to eq(true)
    end

    it 'accepts a key with matching alg' do
      jwk = JWT::JWK.new(rsa_jwk.export.merge(alg: 'RS256'))
      expect(filter.match?(jwk, algorithm: 'RS256')).to eq(true)
    end

    it 'rejects a key with a contradicting alg' do
      jwk = JWT::JWK.new(rsa_jwk.export.merge(alg: 'RS512'))
      expect(filter.match?(jwk, algorithm: 'RS256')).to eq(false)
    end

    it 'rejects a key with a contradicting kty' do
      expect(filter.match?(hmac_jwk, algorithm: 'RS256')).to eq(false)
      expect(filter.match?(rsa_jwk, algorithm: 'HS256')).to eq(false)
    end

    it 'accepts a key with matching use' do
      jwk = JWT::JWK.new(rsa_jwk.export.merge(use: 'sig'))
      expect(filter.match?(jwk, algorithm: 'RS256')).to eq(true)
    end

    it 'rejects a key with use enc' do
      jwk = JWT::JWK.new(rsa_jwk.export.merge(use: 'enc'))
      expect(filter.match?(jwk, algorithm: 'RS256')).to eq(false)
    end

    it 'accepts a key with key_ops including verify' do
      jwk = JWT::JWK.new(rsa_jwk.export.merge(key_ops: %w[verify]))
      expect(filter.match?(jwk, algorithm: 'RS256')).to eq(true)
    end

    it 'rejects a key with key_ops not including verify' do
      jwk = JWT::JWK.new(rsa_jwk.export.merge(key_ops: %w[encrypt]))
      expect(filter.match?(jwk, algorithm: 'RS256')).to eq(false)
    end

    it 'rejects a key whose use and key_ops contradict each other' do
      jwk = JWT::JWK.new(rsa_jwk.export.merge(use: 'sig', key_ops: %w[encrypt]))
      expect(filter.match?(jwk, algorithm: 'RS256')).to eq(false)
    end

    context 'with explicit algorithm' do
      subject(:filter) { described_class.new(algorithm: 'RS256') }

      it 'accepts when the token algorithm matches' do
        expect(filter.match?(rsa_jwk, algorithm: 'RS256')).to eq(true)
      end

      it 'raises when the token algorithm contradicts' do
        expect { filter.match?(rsa_jwk, algorithm: 'HS256') }.to raise_error(JWT::IncorrectAlgorithm)
      end
    end

    context 'with explicit kty' do
      subject(:filter) { described_class.new(kty: 'oct') }

      it 'overrides the kty derived from the algorithm' do
        expect(filter.match?(hmac_jwk, algorithm: 'RS256')).to eq(true)
        expect(filter.match?(rsa_jwk, algorithm: 'RS256')).to eq(false)
      end
    end

    context 'with use and key_ops checks disabled' do
      subject(:filter) { described_class.new(use: nil, key_ops: nil) }

      it 'ignores use and key_ops metadata' do
        jwk = JWT::JWK.new(rsa_jwk.export.merge(use: 'enc', key_ops: %w[encrypt]))
        expect(filter.match?(jwk, algorithm: 'RS256')).to eq(true)
      end
    end

    context 'with a thumbprint whitelist' do
      let(:thumbprint) { JWT::JWK::Thumbprint.new(rsa_jwk).generate }
      subject(:filter) { described_class.new(thumbprints: [thumbprint]) }

      it 'accepts a whitelisted key' do
        expect(filter.match?(rsa_jwk, algorithm: 'RS256')).to eq(true)
      end

      it 'rejects a key that is not whitelisted' do
        other = JWT::JWK.new(OpenSSL::PKey::RSA.generate(2048), 'other')
        expect(filter.match?(other, algorithm: 'RS256')).to eq(false)
      end
    end

    context 'with an empty thumbprint whitelist' do
      subject(:filter) { described_class.new(thumbprints: []) }

      it 'rejects every key' do
        expect(filter.match?(rsa_jwk, algorithm: 'RS256')).to eq(false)
      end
    end
  end

  describe '#select' do
    subject(:filter) { described_class.new }

    it 'returns only the compatible keys' do
      expect(filter.select([rsa_jwk, hmac_jwk], algorithm: 'RS256')).to eq([rsa_jwk])
      expect(filter.select([rsa_jwk, hmac_jwk], algorithm: 'HS256')).to eq([hmac_jwk])
    end
  end
end
