# frozen_string_literal: true

RSpec.describe JWT::JWA::Eddsa do
  # Fixed key from RFC 8037 Appendix A.1
  let(:d_octets) { JWT::Base64.url_decode('nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A') }
  let(:x_octets) { JWT::Base64.url_decode('11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo') }
  let(:private_key) { OpenSSL::PKey.new_raw_private_key('Ed25519', d_octets) }
  let(:public_key) { OpenSSL::PKey.new_raw_public_key('Ed25519', x_octets) }

  let(:jwa) { described_class.new }

  # RFC 8037 Appendix A.4 signing input and signature
  let(:signing_input) do
    header = JWT::Base64.url_encode(JWT::JSON.generate('alg' => 'EdDSA'))
    payload = JWT::Base64.url_encode('Example of Ed25519 signing')
    "#{header}.#{payload}"
  end
  let(:rfc_signature) do
    JWT::Base64.url_decode('hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg')
  end

  describe '.supported?' do
    it 'reports Ed25519 availability of the OpenSSL build' do
      expect(described_class.supported?).to be(true)
    end
  end

  describe '.ed25519_key?' do
    it 'recognizes Ed25519 keys' do
      expect(described_class.ed25519_key?(private_key)).to be(true)
      expect(described_class.ed25519_key?(public_key)).to be(true)
    end

    it 'does not recognize other key types' do
      expect(described_class.ed25519_key?('not a key')).to be(false)
      expect(described_class.ed25519_key?(OpenSSL::PKey::RSA.new(2048))).to be(false)
    end
  end

  describe '.private_key?' do
    it 'is true for a key containing the private part' do
      expect(described_class.private_key?(private_key)).to be(true)
    end

    it 'is false for a public key' do
      expect(described_class.private_key?(public_key)).to be(false)
    end
  end

  describe '#sign' do
    it 'produces the fixed RFC 8037 signature' do
      expect(jwa.sign(data: signing_input, signing_key: private_key)).to eq(rfc_signature)
    end

    it 'raises an encoding error with a non Ed25519 key' do
      expect do
        jwa.sign(data: signing_input, signing_key: OpenSSL::PKey::RSA.new(2048))
      end.to raise_error(JWT::EncodeError, /It has to be an Ed25519/)
    end

    it 'raises an encoding error with a public only key' do
      expect do
        jwa.sign(data: signing_input, signing_key: public_key)
      end.to raise_error(JWT::EncodeError, 'The given key is not a private key')
    end
  end

  describe '#verify' do
    it 'verifies the RFC 8037 signature' do
      expect(jwa.verify(data: signing_input, signature: rfc_signature, verification_key: public_key)).to be(true)
    end

    it 'verifies with the private key as well' do
      expect(jwa.verify(data: signing_input, signature: rfc_signature, verification_key: private_key)).to be(true)
    end

    it 'returns false for a tampered signing input' do
      expect(jwa.verify(data: "#{signing_input}x", signature: rfc_signature, verification_key: public_key)).to be(false)
    end

    it 'returns false for a tampered signature' do
      bad_signature = rfc_signature.dup
      bad_signature.setbyte(-1, bad_signature.getbyte(-1) ^ 0xff)
      expect(jwa.verify(data: signing_input, signature: bad_signature, verification_key: public_key)).to be(false)
    end

    it 'raises a verification error for a nil signature' do
      expect do
        jwa.verify(data: signing_input, signature: nil, verification_key: public_key)
      end.to raise_error(JWT::VerificationError, 'Signature verification raised')
    end

    it 'raises a verification key error when the key is not an Ed25519 key' do
      expect do
        jwa.verify(data: signing_input, signature: rfc_signature, verification_key: 'not a key')
      end.to raise_error(JWT::VerificationKeyError, /It has to be an Ed25519/)
    end
  end

  describe 'algorithm registration' do
    it 'resolves EdDSA through JWA.resolve' do
      expect(JWT::JWA.resolve('EdDSA')).to be_a(described_class)
    end

    it 'matches the algorithm name case insensitively' do
      expect(JWT::JWA.resolve('eddsa').valid_alg?('EdDSA')).to be(true)
    end
  end
end
