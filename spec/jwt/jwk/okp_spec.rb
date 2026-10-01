# frozen_string_literal: true

# The key material and the detached signature used in this spec are the
# public test vectors from RFC 8037 (Appendix A).
RSpec.describe JWT::JWK::OKP do
  # RFC 8037, Appendix A.1
  let(:private_params) do
    {
      kty: 'OKP',
      crv: 'Ed25519',
      d: 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A',
      x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo'
    }
  end

  # RFC 8037, Appendix A.2
  let(:public_params) do
    {
      kty: 'OKP',
      crv: 'Ed25519',
      x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo'
    }
  end

  # RFC 8037, Appendix A.4
  let(:rfc8037_jws) do
    'eyJhbGciOiJFZERTQSJ9.' \
      'RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.' \
      'hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg'
  end

  let(:rfc8037_signing_input) { rfc8037_jws.split('.')[0..1].join('.') }
  let(:rfc8037_signature) { JWT::Base64.url_decode(rfc8037_jws.split('.')[2]) }

  describe '.new' do
    context 'when a private JWK hash is given' do
      subject(:jwk) { described_class.new(private_params) }

      it 'creates an instance and treats it as private' do
        expect(jwk).to be_a(described_class)
        expect(jwk.private?).to eq(true)
      end
    end

    context 'when a public JWK hash is given' do
      subject(:jwk) { described_class.new(public_params) }

      it 'creates an instance and treats it as public' do
        expect(jwk).to be_a(described_class)
        expect(jwk.private?).to eq(false)
      end
    end

    context 'when an OpenSSL private key is given' do
      let(:keypair) do
        OpenSSL::PKey.new_raw_private_key('ED25519', JWT::Base64.url_decode(private_params[:d]))
      end

      subject(:jwk) { described_class.new(keypair) }

      it 'parses the coordinates of the key' do
        expect(jwk[:kty]).to eq('OKP')
        expect(jwk[:crv]).to eq('Ed25519')
        expect(jwk[:x]).to eq(private_params[:x])
        expect(jwk[:d]).to eq(private_params[:d])
        expect(jwk.private?).to eq(true)
      end
    end

    context 'when an OpenSSL public key is given' do
      let(:keypair) do
        OpenSSL::PKey.new_raw_public_key('ED25519', JWT::Base64.url_decode(public_params[:x]))
      end

      subject(:jwk) { described_class.new(keypair) }

      it 'parses the public coordinates only' do
        expect(jwk[:x]).to eq(public_params[:x])
        expect(jwk[:d]).to be_nil
        expect(jwk.private?).to eq(false)
      end
    end

    context 'when an OpenSSL key of an unsupported curve is given' do
      subject { described_class.new(OpenSSL::PKey.generate_key('X25519')) }

      it 'raises an error' do
        expect { subject }.to raise_error(JWT::JWKError, "Unsupported curve 'X25519'")
      end
    end

    context 'when another OKP JWK is given' do
      let(:jwk) { described_class.new(private_params) }

      it 'copies the key including its private parameters' do
        copy = described_class.new(jwk)
        expect(copy).to be_a(described_class)
        expect(copy.private?).to eq(true)
        expect(copy.export(include_private: true)).to include(private_params)
      end
    end

    context 'when a number is given' do
      subject { described_class.new(1234) }

      it 'raises an argument error' do
        expect { subject }.to raise_error(ArgumentError, 'key must be of type OpenSSL::PKey::PKey or Hash with key parameters')
      end
    end

    context 'when an unsupported curve is given' do
      subject { described_class.new(kty: 'OKP', crv: 'X25519', x: public_params[:x]) }

      it 'raises an error' do
        expect { subject }.to raise_error(JWT::JWKError, "Unsupported curve 'X25519'")
      end
    end

    context 'when the kty is not OKP' do
      subject { described_class.new(kty: 'EC', crv: 'Ed25519', x: public_params[:x]) }

      it 'raises an error' do
        expect { subject }.to raise_error(JWT::JWKError, "Incorrect 'kty' value: EC, expected OKP")
      end
    end

    context 'when the public key part is missing' do
      subject { described_class.new(kty: 'OKP', crv: 'Ed25519') }

      it 'raises an error' do
        expect { subject }.to raise_error(JWT::JWKError, 'Key format is invalid for OKP')
      end
    end

    context 'when the x parameter has the wrong length' do
      subject { described_class.new(kty: 'OKP', crv: 'Ed25519', x: JWT::Base64.url_encode('short')) }

      it 'raises an error' do
        expect { subject }.to raise_error(JWT::JWKError, "The 'x' parameter has to be 32 bytes for curve 'ED25519'")
      end
    end

    context 'when the d parameter has the wrong length' do
      subject do
        described_class.new(kty: 'OKP', crv: 'Ed25519', x: public_params[:x], d: JWT::Base64.url_encode('short'))
      end

      it 'raises an error' do
        expect { subject }.to raise_error(JWT::JWKError, "The 'd' parameter has to be 32 bytes for curve 'ED25519'")
      end
    end

    context 'when the private and public key parts do not match' do
      let(:other_public) do
        JWT::Base64.url_encode(OpenSSL::PKey.generate_key('ED25519').raw_public_key)
      end

      subject do
        described_class.new(kty: 'OKP', crv: 'Ed25519', x: other_public, d: private_params[:d])
      end

      it 'raises an error' do
        expect { subject }.to raise_error(JWT::JWKError, 'The private and public key parts do not match')
      end
    end

    context 'when x is not valid base64url' do
      subject { described_class.new(kty: 'OKP', crv: 'Ed25519', x: '@@@@') }

      it 'raises an error' do
        expect { subject }.to raise_error(JWT::JWKError, "The 'x' parameter is not valid base64url encoded data")
      end
    end

    context 'when OpenSSL cannot build the key' do
      it 'wraps the OpenSSL error in a JWK error' do
        allow(OpenSSL::PKey).to receive(:new_raw_public_key).and_raise(OpenSSL::PKey::PKeyError.new('provider failure'))
        expect do
          described_class.new(public_params)
        end.to raise_error(JWT::JWKError, "Key could not be created for curve 'Ed25519': provider failure")
      end
    end

    context 'when reading the raw private key of a public OpenSSL key fails' do
      let(:keypair) do
        OpenSSL::PKey.new_raw_public_key('ED25519', JWT::Base64.url_decode(public_params[:x]))
      end

      it 'treats the key as public' do
        expect(described_class.new(keypair).private?).to eq(false)
      end
    end
  end

  describe '#export' do
    context 'when a private key is exported without options' do
      subject(:exported) { described_class.new(private_params).export }

      it 'contains only the public key parameters' do
        expect(exported).to include(:kty, :crv, :x, :kid)
        expect(exported[:kty]).to eq('OKP')
        expect(exported[:crv]).to eq('Ed25519')
        expect(exported[:x]).to eq(public_params[:x])
        expect(exported).not_to include(:d)
      end
    end

    context 'when a public key is exported without options' do
      subject(:exported) { described_class.new(public_params).export }

      it 'matches the RFC 8037 public key representation apart from the kid' do
        expect(exported).to include(public_params)
        expect(exported).not_to include(:d)
      end
    end

    context 'when the private part is explicitly requested' do
      subject(:exported) { described_class.new(private_params).export(include_private: true) }

      it 'contains the private key parameter' do
        expect(exported).to include(private_params)
      end
    end

    context 'when a common parameter is given' do
      subject { described_class.new(private_params, use: 'sig').export }

      it 'is included in the export' do
        expect(subject[:use]).to eq('sig')
        expect(subject).not_to include(:d)
      end
    end
  end

  describe '#members' do
    subject(:members) { described_class.new(private_params).members }

    it 'returns only the public key members' do
      expect(members).to eq(kty: 'OKP', crv: 'Ed25519', x: private_params[:x])
    end
  end

  describe 'thumbprint' do
    # RFC 8037, Appendix A.3
    let(:expected_thumbprint) { 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k' }

    it 'matches the RFC 8037 thumbprint for the public key' do
      thumbprint = JWT::JWK::Thumbprint.new(described_class.new(public_params)).generate
      expect(thumbprint).to eq(expected_thumbprint)
    end

    it 'matches the RFC 8037 thumbprint for the private key as well' do
      thumbprint = JWT::JWK::Thumbprint.new(described_class.new(private_params)).generate
      expect(thumbprint).to eq(expected_thumbprint)
    end

    it 'is used as the kid when the RFC 7638 thumbprint generator is configured' do
      JWT.configure { |config| config.jwk.kid_generator_type = :rfc7638_thumbprint }
      expect(described_class.new(public_params).kid).to eq(expected_thumbprint)
    ensure
      JWT.configuration.reset!
    end
  end

  describe '#keypair and #public_key' do
    let(:jwk) { described_class.new(private_params) }

    it 'returns OpenSSL Ed25519 keys' do
      expect(jwk.keypair).to be_a(OpenSSL::PKey::PKey)
      expect(jwk.keypair.oid).to eq('ED25519')
      expect(jwk.public_key).to be_a(OpenSSL::PKey::PKey)
      expect(jwk.public_key.oid).to eq('ED25519')
    end
  end

  describe '.openssl_curve' do
    it 'returns the OpenSSL key type for a supported curve' do
      expect(described_class.openssl_curve('Ed25519')).to eq('ED25519')
    end

    it 'raises an error for an unsupported curve' do
      expect do
        described_class.openssl_curve('Ed448')
      end.to raise_error(JWT::JWKError, "Unsupported curve 'Ed448'")
    end
  end

  describe '.import' do
    it 'round-trips a private key export' do
      jwk = described_class.import(described_class.new(private_params).export(include_private: true))
      expect(jwk).to be_a(described_class)
      expect(jwk.private?).to eq(true)
      expect(jwk.export(include_private: true)).to include(private_params)
    end
  end

  describe '#sign and #verify' do
    let(:data) { 'data_to_sign' }

    context 'with a private JWK' do
      let(:jwk) { described_class.new(private_params) }

      it 'produces a signature that the public JWK verifies' do
        signature = jwk.sign(data: data)
        expect(signature.bytesize).to eq(64)
        expect(described_class.new(public_params).verify(data: data, signature: signature)).to be(true)
      end

      it 'produces deterministic signatures matching a fresh sign operation' do
        first  = jwk.sign(data: data)
        second = jwk.sign(data: data)
        expect(first).to eq(second)
      end

      it 'verifies the RFC 8037 fixed signature with the public key exported from the private key' do
        public_jwk = JWT::JWK.new(jwk.export)
        expect(public_jwk.verify(data: rfc8037_signing_input, signature: rfc8037_signature)).to be(true)
      end

      it 'verifies a signature it produced itself' do
        signature = jwk.sign(data: data)
        expect(jwk.verify(data: data, signature: signature)).to be(true)
      end

      it 'returns false for a tampered signature' do
        signature = jwk.sign(data: data)
        tampered = signature.bytes.map { |byte| byte ^ 0xff }.pack('C*')
        expect(described_class.new(public_params).verify(data: data, signature: tampered)).to be(false)
      end

      it 'returns false for a malformed signature' do
        expect(described_class.new(public_params).verify(data: data, signature: 'short')).to be(false)
      end
    end

    context 'with a public only JWK' do
      let(:jwk) { described_class.new(public_params) }

      it 'cannot sign' do
        expect { jwk.sign(data: data) }.to raise_error(JWT::EncodeError, 'The given key is not a private key')
      end

      it 'cannot be used for encoding a JWT' do
        expect do
          JWT.encode({ data: 'payload' }, jwk, 'EdDSA')
        end.to raise_error(JWT::EncodeError, 'The given key is not a private key')
      end
    end

    context 'when used through JWT.encode and JWT.decode' do
      let(:jwk) { described_class.new(private_params) }

      it 'encodes a token and decodes it with a JWK built from the public export' do
        token = JWT.encode({ 'message' => 'hello' }, jwk, 'EdDSA')
        expect(token.split('.').size).to eq(3)

        public_jwk = JWT::JWK.new(jwk.export)
        payload, decoded_header = JWT.decode(token, public_jwk, true, algorithms: ['EdDSA'])
        expect(payload).to eq('message' => 'hello')
        expect(decoded_header['alg']).to eq('EdDSA')
      end

      it 'decodes the RFC 8037 example JWS with the public key JWK' do
        segments = rfc8037_jws.split('.')
        signing_input = "#{segments[0]}.#{segments[1]}"
        signature = JWT::Base64.url_decode(segments[2])
        expect(described_class.new(public_params).verify(data: signing_input, signature: signature)).to be(true)
      end

      it 'encodes a token and decodes it through a JWKS containing the public export' do
        token = JWT.encode({ 'data' => 'something' }, jwk, 'EdDSA', kid: jwk.kid)
        jwks = JWT::JWK::Set.new(keys: [jwk.export])
        payload, header = JWT.decode(token, nil, true, algorithms: ['EdDSA'], jwks: jwks)
        expect(payload).to eq('data' => 'something')
        expect(header['alg']).to eq('EdDSA')
      end
    end
  end

  describe '#jwa' do
    it 'defaults to EdDSA' do
      expect(described_class.new(public_params).jwa).to be_a(JWT::JWA::Eddsa)
    end

    it 'uses the explicit alg parameter when given' do
      jwk = described_class.new(public_params, alg: 'EdDSA')
      expect(jwk.jwa).to be_a(JWT::JWA::Eddsa)
    end
  end
end
