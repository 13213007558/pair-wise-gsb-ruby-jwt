# frozen_string_literal: true

RSpec.describe JWT::JWA::Eddsa do
  let(:private_key) { OpenSSL::PKey.generate_key('ED25519') }
  let(:public_key) { OpenSSL::PKey.new_raw_public_key('ED25519', private_key.raw_public_key) }
  let(:data) { 'signing input' }
  let(:instance) { described_class.new }
  let(:signature) { instance.sign(data: data, signing_key: private_key) }

  describe '.new' do
    it 'registers the EdDSA algorithm' do
      expect(JWT::JWA.resolve('EdDSA')).to be_a(described_class)
    end
  end

  describe '#header' do
    it 'returns the EdDSA header' do
      expect(instance.header).to eq('alg' => 'EdDSA')
    end
  end

  describe '#sign' do
    it 'produces a 64 byte Ed25519 signature' do
      expect(signature.bytesize).to eq(64)
    end

    it 'is deterministic' do
      expect(signature).to eq(instance.sign(data: data, signing_key: private_key))
    end

    context 'when the key is not an Ed25519 key' do
      it 'raises an encode error for an EC key' do
        expect do
          instance.sign(data: data, signing_key: OpenSSL::PKey::EC.generate('prime256v1'))
        end.to raise_error(JWT::EncodeError, /It has to be an OpenSSL Ed25519/)
      end

      it 'raises an encode error for a String' do
        expect do
          instance.sign(data: data, signing_key: 'secret')
        end.to raise_error(JWT::EncodeError, /It has to be an OpenSSL Ed25519/)
      end
    end

    context 'when OpenSSL raises an error while signing' do
      it 'wraps the error in an encode error' do
        allow(private_key).to receive(:sign).and_raise(OpenSSL::PKey::PKeyError.new('provider failure'))
        expect do
          instance.sign(data: data, signing_key: private_key)
        end.to raise_error(JWT::EncodeError, 'provider failure')
      end
    end

    context 'when the key is a public key' do
      it 'raises an encode error' do
        expect do
          instance.sign(data: data, signing_key: public_key)
        end.to raise_error(JWT::EncodeError, 'The given key is not a private key')
      end
    end
  end

  describe '#verify' do
    it 'returns true for a valid signature' do
      expect(instance.verify(data: data, signature: signature, verification_key: public_key)).to be(true)
    end

    it 'verifies with a private key as well' do
      expect(instance.verify(data: data, signature: signature, verification_key: private_key)).to be(true)
    end

    it 'returns false when the signature is for other data' do
      expect(instance.verify(data: 'other data', signature: signature, verification_key: public_key)).to be(false)
    end

    it 'returns false for a malformed signature' do
      expect(instance.verify(data: data, signature: 'short', verification_key: public_key)).to be(false)
    end

    it 'raises a verification error for a non-string signature' do
      expect do
        instance.verify(data: data, signature: nil, verification_key: public_key)
      end.to raise_error(JWT::VerificationError, 'Signature verification raised')
    end

    context 'when the verification key is not an Ed25519 key' do
      it 'raises a verification key error' do
        expect do
          instance.verify(data: data, signature: signature, verification_key: 'secret')
        end.to raise_error(JWT::VerificationKeyError, /It has to be an OpenSSL Ed25519/)
      end
    end
  end

  describe '.ed25519_key?' do
    it 'recognizes an Ed25519 key by its OID' do
      expect(described_class.ed25519_key?(private_key)).to be(true)
    end

    it 'does not recognize keys of another type' do
      expect(described_class.ed25519_key?('not-a-key')).to be(false)
      expect(described_class.ed25519_key?(OpenSSL::PKey::EC.generate('prime256v1'))).to be(false)
    end

    it 'returns false when the OID of the key cannot be read' do
      key = OpenSSL::PKey.generate_key('ED25519')
      allow(key).to receive(:oid).and_raise(OpenSSL::PKey::PKeyError.new('no OID'))
      expect(described_class.ed25519_key?(key)).to be(false)
    end
  end

  describe 'RFC 8037 Appendix A test vector' do
    let(:x) { '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' }
    let(:jwt) do
      'eyJhbGciOiJFZERTQSJ9.' \
        'RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.' \
        'hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg'
    end

    it 'verifies the fixed signature and reproduces it from the private seed' do
      segments = jwt.split('.')
      signing_input = "#{segments[0]}.#{segments[1]}"
      signature = JWT::Base64.url_decode(segments[2])

      public_key = OpenSSL::PKey.new_raw_public_key('ED25519', JWT::Base64.url_decode(x))
      expect(instance.verify(data: signing_input, signature: signature, verification_key: public_key)).to be(true)

      d = 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A'
      private_key = OpenSSL::PKey.new_raw_private_key('ED25519', JWT::Base64.url_decode(d))
      expect(instance.sign(data: signing_input, signing_key: private_key)).to eq(signature)
    end
  end
end
