# frozen_string_literal: true

RSpec.describe JWT::JWK::OKP do
  # Fixed test key from RFC 8037 Appendix A.1/A.2
  let(:x) { '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' }
  let(:d) { 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A' }

  let(:private_jwk_hash) { { kty: 'OKP', crv: 'Ed25519', x: x, d: d } }
  let(:public_jwk_hash) { { kty: 'OKP', crv: 'Ed25519', x: x } }

  let(:private_jwk) { described_class.import(private_jwk_hash) }
  let(:public_jwk) { described_class.import(public_jwk_hash) }

  # RFC 8037 Appendix A.4 (detached content) Ed25519 JWS
  let(:protected_header) { 'eyJhbGciOiJFZERTQSJ9' }
  let(:encoded_payload) { 'RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc' }
  let(:rfc_signature) { 'hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg' }
  let(:signing_input) { "#{protected_header}.#{encoded_payload}" }

  describe '.new / .import' do
    context 'when a private key JWK hash is given' do
      it 'creates a private JWK' do
        expect(private_jwk).to be_a(described_class)
        expect(private_jwk.private?).to be(true)
      end
    end

    context 'when a public key JWK hash is given' do
      it 'creates a public JWK' do
        expect(public_jwk).to be_a(described_class)
        expect(public_jwk.private?).to be(false)
      end

      it 'cannot sign' do
        expect { public_jwk.sign(data: signing_input) }.to raise_error(JWT::EncodeError, 'The given key is not a private key')
      end
    end

    context 'when only the private part d is given' do
      subject(:jwk) { described_class.import(kty: 'OKP', crv: 'Ed25519', d: d) }

      it 'derives the public part x from the private key' do
        expect(jwk[:x]).to eq(x)
      end

      it 'reproduces the RFC 8037 signature' do
        expect(JWT::Base64.url_encode(jwk.sign(data: signing_input))).to eq(rfc_signature)
      end
    end

    context 'when parsed from JSON with string keys' do
      it 'creates an OKP JWK' do
        expect(JWT::JWK.import(JSON.parse(JSON.generate(private_jwk_hash)))).to be_a(described_class)
      end
    end

    context 'when an OpenSSL Ed25519 key is given' do
      let(:openssl_key) { OpenSSL::PKey.new_raw_private_key('Ed25519', JWT::Base64.url_decode(d)) }

      it 'creates an OKP JWK from a private key' do
        jwk = JWT::JWK.new(openssl_key)
        expect(jwk).to be_a(described_class)
        expect(jwk.private?).to be(true)
        expect(jwk[:x]).to eq(x)
        expect(jwk[:d]).to eq(d)
      end

      it 'creates an OKP JWK from a public key' do
        public_key = OpenSSL::PKey.new_raw_public_key('Ed25519', JWT::Base64.url_decode(x))
        jwk = JWT::JWK.new(public_key)
        expect(jwk).to be_a(described_class)
        expect(jwk.private?).to be(false)
        expect(jwk[:x]).to eq(x)
      end

      it 'round trips through export and import' do
        jwk = described_class.new(openssl_key)
        expect(described_class.import(jwk.export(include_private: true)).private?).to be(true)
        expect(described_class.import(jwk.export).private?).to be(false)
      end

      it 'rejects an unsupported OpenSSL curve' do
        unsupported = OpenSSL::PKey.generate_key('X25519')
        expect { described_class.new(unsupported) }.to raise_error(JWT::JWKError, /Unsupported curve/)
      end
    end

    context 'when the key is neither a Hash nor an Ed25519 OpenSSL key' do
      it 'raises an argument error' do
        expect { described_class.new(1234) }.to raise_error(ArgumentError, /must be an Ed25519 OpenSSL key or a Hash/)
      end
    end

    context 'validation' do
      it 'rejects a wrong kty' do
        expect do
          described_class.import(kty: 'EC', crv: 'Ed25519', x: x)
        end.to raise_error(JWT::JWKError, "Incorrect 'kty' value: EC, expected OKP")
      end

      it 'rejects an unsupported curve' do
        expect do
          described_class.import(kty: 'OKP', crv: 'X25519', x: x)
        end.to raise_error(JWT::JWKError, "Unsupported curve 'X25519'")

        expect do
          described_class.import(kty: 'OKP', crv: 'Ed448', x: x)
        end.to raise_error(JWT::JWKError, "Unsupported curve 'Ed448'")
      end

      it 'rejects a key without x and d' do
        expect do
          described_class.import(kty: 'OKP', crv: 'Ed25519')
        end.to raise_error(JWT::JWKError, /at least one of the x or d parameters/)
      end

      it 'rejects an x parameter with the wrong byte length' do
        expect do
          described_class.import(kty: 'OKP', crv: 'Ed25519', x: JWT::Base64.url_encode('short'))
        end.to raise_error(JWT::JWKError, "Invalid OKP key: the 'x' parameter must be 32 bytes, got 5")
      end

      it 'rejects a d parameter with the wrong byte length' do
        expect do
          described_class.import(kty: 'OKP', crv: 'Ed25519', d: JWT::Base64.url_encode('short'))
        end.to raise_error(JWT::JWKError, "Invalid OKP key: the 'd' parameter must be 32 bytes, got 5")
      end

      it 'rejects a 32 byte d that does not match the given x' do
        mismatching_d = 'aWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A'
        expect do
          described_class.import(kty: 'OKP', crv: 'Ed25519', x: x, d: mismatching_d)
        end.to raise_error(JWT::JWKError, 'Invalid OKP key: the public key (x) does not match the private key (d)')
      end

      it 'rejects cryptographic attributes being passed as extra params' do
        expect do
          described_class.new(private_jwk_hash, { crv: 'Ed25519' })
        end.to raise_error(ArgumentError, 'cannot overwrite cryptographic key attributes')
      end
    end
  end

  describe '#export' do
    it 'never includes private parameters by default' do
      exported = private_jwk.export
      expect(exported).to include(:kty, :crv, :x, :kid)
      expect(exported).not_to include(:d)
    end

    it 'does not include private parameters for an imported public key either' do
      exported = described_class.import(private_jwk.export).export
      expect(exported).not_to include(:d)
    end

    it 'includes d only when include_private is requested on a private key' do
      exported = private_jwk.export(include_private: true)
      expect(exported[:d]).to eq(d)
      expect(exported[:x]).to eq(x)
    end

    it 'keeps common parameters such as kid or use' do
      jwk = described_class.new(public_jwk_hash, kid: 'custom-kid', use: 'sig')
      exported = jwk.export
      expect(exported[:kid]).to eq('custom-kid')
      expect(exported[:use]).to eq('sig')
    end
  end

  describe '#members' do
    it 'returns exactly the public JWK members' do
      expect(public_jwk.members).to eq(kty: 'OKP', crv: 'Ed25519', x: x)
    end
  end

  describe 'signing and verifying with the RFC 8037 vector' do
    it 'signs the RFC signing input into the RFC signature' do
      signature = private_jwk.sign(data: signing_input)
      expect(JWT::Base64.url_encode(signature)).to eq(rfc_signature)
    end

    it 'verifies the original signature with the public JWK' do
      expect(public_jwk.verify(data: signing_input, signature: JWT::Base64.url_decode(rfc_signature))).to be(true)
    end

    it 'verifies the original signature with the public JWK exported from the private JWK' do
      exported_public_jwk = JWT::JWK.import(private_jwk.export)
      expect(exported_public_jwk.private?).to be(false)
      expect(exported_public_jwk.verify(data: signing_input, signature: JWT::Base64.url_decode(rfc_signature))).to be(true)
    end

    it 'fails verification when the data is tampered' do
      expect(public_jwk.verify(data: "#{signing_input}x", signature: JWT::Base64.url_decode(rfc_signature))).to be(false)
    end
  end

  describe '#jwa' do
    it 'resolves to EdDSA by default' do
      expect(private_jwk.jwa).to be_a(JWT::JWA::Eddsa)
    end

    it 'uses an explicitly set alg parameter' do
      jwk = described_class.new(private_jwk_hash, alg: 'EdDSA')
      expect(jwk.verify(data: signing_input, signature: private_jwk.sign(data: signing_input))).to be(true)
    end
  end

  describe 'thumbprint' do
    it 'matches the canonical RFC 8037 Appendix A.3 thumbprint' do
      # RFC 8037 A.3: kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k
      expect(JWT::JWK::Thumbprint.new(public_jwk).to_s).to eq('kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k')
    end

    it 'is identical for the public JWK and the private JWK' do
      expect(JWT::JWK::Thumbprint.new(private_jwk).to_s).to eq(JWT::JWK::Thumbprint.new(public_jwk).to_s)
    end
  end

  describe 'full token encode and decode' do
    it 'encodes with the private JWK and decodes with the exported public JWK' do
      token = JWT.encode({ 'data' => 'hello' }, private_jwk, 'EdDSA')
      payload, header = JWT.decode(token, JWT::JWK.import(private_jwk.export), true, algorithms: ['EdDSA'])
      expect(header['alg']).to eq('EdDSA')
      expect(payload).to eq('data' => 'hello')
    end

    it 'decodes a token using a JWK set' do
      token = JWT.encode({ 'data' => 'hello' }, private_jwk, 'EdDSA', kid: 'the-kid')
      jwks = JWT::JWK::Set.new([public_jwk_hash.merge(kid: 'the-kid')])
      payload, = JWT.decode(token, nil, true, algorithms: ['EdDSA'], jwks: jwks)
      expect(payload).to eq('data' => 'hello')
    end

    it 'refuses decoding when EdDSA is not among the allowed algorithms' do
      token = JWT.encode({ 'data' => 'hello' }, private_jwk, 'EdDSA')
      expect do
        JWT.decode(token, public_jwk, true, algorithms: ['ES256'])
      end.to raise_error(JWT::IncorrectAlgorithm)
    end
  end

  describe '#[]=' do
    it 'forbids overwriting key material' do
      expect { public_jwk[:x] = 'something' }.to raise_error(ArgumentError, 'cannot overwrite cryptographic key attributes')
      expect { public_jwk[:kty] = 'something' }.to raise_error(ArgumentError)
      expect { private_jwk[:d] = 'something' }.to raise_error(ArgumentError)
    end
  end
end
