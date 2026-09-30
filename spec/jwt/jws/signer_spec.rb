# frozen_string_literal: true

RSpec.describe JWT::JWS::Signer do
  let(:payload) { JWT::Base64.url_encode(JWT::JSON.generate('pay' => 'load')) }

  subject(:signer) { described_class.new(algorithm: 'HS256', key: 'secret', protected_header: protected_header, header: header) }

  let(:protected_header) { {} }
  let(:header) { {} }

  describe '#sign' do
    it 'places the algorithm in the protected header' do
      signature = signer.sign(payload)
      decoded = JWT::JSON.parse(JWT::Base64.url_decode(signature.encoded_protected_header))

      expect(decoded).to include('alg' => 'HS256')
    end

    it 'produces a signature verifiable against the same key' do
      signature = signer.sign(payload)
      compact = [signature.encoded_protected_header, payload, signature.encoded_signature].join('.')
      token = JWT::EncodedToken.new(compact)

      expect(token.valid_signature?(algorithm: 'HS256', key: 'secret')).to be(true)
    end

    context 'with unprotected headers' do
      let(:header) { { 'kid' => 'unprotected' } }

      it 'keeps them outside the protected header' do
        signature = signer.sign(payload)
        decoded = JWT::JSON.parse(JWT::Base64.url_decode(signature.encoded_protected_header))

        expect(signature.unprotected_header).to eq('kid' => 'unprotected')
        expect(decoded).not_to include('kid')
      end
    end

    context 'with protected headers' do
      let(:protected_header) { { 'kid' => 'protected' } }

      it 'merges them with the generated algorithm' do
        signature = signer.sign(payload)
        decoded = JWT::JSON.parse(JWT::Base64.url_decode(signature.encoded_protected_header))

        expect(decoded).to eq('alg' => 'HS256', 'kid' => 'protected')
      end
    end

    context 'with symbol keyed headers' do
      let(:protected_header) { { kid: 'one' } }

      it 'normalizes them to strings' do
        signature = signer.sign(payload)
        decoded = JWT::JSON.parse(JWT::Base64.url_decode(signature.encoded_protected_header))

        expect(decoded).to include('kid' => 'one')
      end
    end

    context 'with the same parameter in both headers' do
      let(:protected_header) { { 'kid' => 'one' } }
      let(:header) { { 'kid' => 'two' } }

      it 'raises an encoding error' do
        expect { signer }.to raise_error(JWT::EncodeError, /must not be present in both protected and unprotected headers/)
      end
    end

    context 'with a mismatching alg in the protected header' do
      let(:protected_header) { { 'alg' => 'RS256' } }

      it 'raises an algorithm error' do
        expect { signer }.to raise_error(JWT::IncorrectAlgorithm, /do not match/)
      end
    end

    context 'with a matching alg in the protected header' do
      let(:protected_header) { { 'alg' => 'hs256' } }

      it 'keeps the provided value' do
        signature = signer.sign(payload)
        decoded = JWT::JSON.parse(JWT::Base64.url_decode(signature.encoded_protected_header))

        expect(decoded['alg']).to eq('hs256')
      end
    end

    context 'with headers that are not hashes' do
      let(:header) { 'not-a-hash' }

      it 'raises an encoding error' do
        expect { signer }.to raise_error(JWT::EncodeError, 'Unprotected header must be a Hash')
      end
    end
  end
end
