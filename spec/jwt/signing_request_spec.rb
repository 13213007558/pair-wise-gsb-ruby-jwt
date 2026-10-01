# frozen_string_literal: true

require_relative '../spec_support/external_signer'

RSpec.describe JWT::SigningRequest do
  let(:payload) { { 'data' => 'approval', 'n' => 42 } }
  let(:headers) { { 'kid' => 'hsm-key-1' } }

  let(:rsa_key) { test_pkey('rsa-2048-private.pem') }
  let(:rsa_public) { test_pkey('rsa-2048-public.pem') }
  let(:other_rsa_public) { test_pkey('rsa-2048-wrong-public.pem') }
  let(:ec256_key) { test_pkey('ec256-private.pem') }
  let(:ec256_public) { test_pkey('ec256-public.pem') }
  let(:ec256k_key) { test_pkey('ec256k-private.pem') }
  let(:ec384_key) { test_pkey('ec384-private.pem') }
  let(:ec512_key) { test_pkey('ec512-private.pem') }

  def finalized_token(request, signature:, key:)
    described_class.finalize(request, signature: signature, public_key: key)
  end

  describe '.prepare' do
    it 'builds a request with fixed algorithm and encoded segments' do
      request = described_class.prepare(payload: payload, algorithm: 'PS256', headers: headers)

      expect(request.algorithm).to eq('PS256')
      expect(request.header).to eq('alg' => 'PS256', 'kid' => 'hsm-key-1')
      expect(request.payload).to eq(payload)
      expect(request.signing_input).to eq("#{request.encoded_header}.#{request.encoded_payload}")
    end

    it 'keeps an alg already present in the header' do
      request = described_class.prepare(payload: payload, algorithm: 'PS256', headers: { 'alg' => 'PS256' })
      expect(request.header['alg']).to eq('PS256')
    end

    it 'does not require the private key' do
      expect { described_class.prepare(payload: payload, algorithm: 'PS256') }.not_to raise_error
    end

    %w[HS256 HS384 HS512 none].each do |alg|
      it "rejects the symmetric #{alg} algorithm" do
        expect { described_class.prepare(payload: payload, algorithm: alg) }
          .to raise_error(JWT::EncodeError, /asymmetric algorithms/)
      end
    end

    it 'rejects unknown algorithms' do
      expect { described_class.prepare(payload: payload, algorithm: 'NOPE') }
        .to raise_error(JWT::EncodeError, /asymmetric algorithms/)
    end

    it 'rejects a public key of the wrong type' do
      expect { described_class.prepare(payload: payload, algorithm: 'PS256', public_key: ec256_public) }
        .to raise_error(JWT::VerificationKeyError, /OpenSSL::PKey::RSA/)
    end

    it 'rejects a public key of the wrong ECDSA curve via finalize' do
      request = described_class.prepare(payload: payload, algorithm: 'ES384')
      signer = SpecSupport::ExternalSigner.new(private_key: ec384_key)
      expect { finalized_token(request, signature: signer.sign(request), key: ec256_public) }
        .to raise_error(JWT::IncorrectAlgorithm, /verification key/)
    end

    it 'accepts a matching public key while preparing' do
      expect { described_class.prepare(payload: payload, algorithm: 'ES256', public_key: ec256_public) }
        .not_to raise_error
    end

    it 'validates numeric claims while preparing' do
      expect do
        described_class.prepare(payload: { 'exp' => 'soon' }, algorithm: 'PS256')
      end.to raise_error(JWT::InvalidPayload)
    end
  end

  describe 'serialization' do
    let(:request) { described_class.prepare(payload: payload, algorithm: 'ES256', headers: headers) }

    it 'is JSON serializable and restores all fields' do
      restored = described_class.from_json(request.to_json)

      expect(restored.algorithm).to eq(request.algorithm)
      expect(restored.encoded_header).to eq(request.encoded_header)
      expect(restored.encoded_payload).to eq(request.encoded_payload)
      expect(restored.signing_input).to eq(request.signing_input)
    end

    it 'survives a full JSON round trip through an external system' do
      wire = JSON.parse(request.to_json)

      expect(wire).to include(
        'alg' => 'ES256',
        'protected' => request.encoded_header,
        'payload' => request.encoded_payload,
        'signing_input' => request.signing_input
      )
    end

    it 'can be restored from a Hash' do
      restored = described_class.from_h(request.to_h)
      expect(restored.signing_input).to eq(request.signing_input)
    end

    it 'rejects invalid JSON' do
      expect { described_class.from_json('{not-json') }.to raise_error(JWT::MalformedTokenError)
    end

    it 'rejects JSON that is not an object' do
      expect { described_class.from_json('[]') }.to raise_error(JWT::MalformedTokenError, /JSON object/)
    end

    it 'rejects a request missing required fields' do
      expect { described_class.from_h('alg' => 'PS256') }
        .to raise_error(JWT::MalformedTokenError, /missing one of the alg, protected or payload fields/)
    end

    it 'rejects malformed segment encoding' do
      hash = request.to_h.merge('protected' => '!!!not-base64')
      expect { described_class.from_h(hash) }.to raise_error(JWT::MalformedTokenError, /segment encoding/)
    end

    it 'rejects a signing input that does not match the segments' do
      hash = request.to_h.merge('signing_input' => 'something.else')
      expect { described_class.from_h(hash) }
        .to raise_error(JWT::MalformedTokenError, /does not match/)
    end

    it 'rejects a protected header alg different from the request alg' do
      hash = request.to_h.merge('alg' => 'ES384')
      expect { described_class.from_h(hash) }
        .to raise_error(JWT::MalformedTokenError, /does not match the request algorithm/)
    end
  end

  describe '.finalize' do
    shared_examples 'a finalized externally signed token' do |alg, key, encodings, ecdsa_format: nil|
      encodings.each do |encoding|
        context "#{alg} with a #{encoding} encoded signature" do
          let(:request) { described_class.prepare(payload: payload, algorithm: alg, headers: headers) }

          it 'verifies the signature and produces a valid token' do
            signer = SpecSupport::ExternalSigner.new(
              private_key: send(key), encoding: encoding, ecdsa_format: ecdsa_format || :der
            )
            signature = signer.sign(request.to_json)

            token = finalized_token(request.to_json, signature: signature, key: send(key))

            expect(token.jwt.split('.').length).to eq(3)
            encoded = JWT::EncodedToken.new(token.jwt)
            expect(encoded.valid_signature?(algorithm: alg, key: send(key))).to be(true)
            expect(encoded.header).to eq('alg' => alg, 'kid' => 'hsm-key-1')
          end
        end
      end
    end

    it_behaves_like 'a finalized externally signed token', 'RS256', :rsa_key, %i[raw base64 base64url]
    it_behaves_like 'a finalized externally signed token', 'RS384', :rsa_key, %i[raw]
    it_behaves_like 'a finalized externally signed token', 'RS512', :rsa_key, %i[raw]
    it_behaves_like 'a finalized externally signed token', 'PS256', :rsa_key, %i[raw base64 base64url]
    it_behaves_like 'a finalized externally signed token', 'PS384', :rsa_key, %i[base64]
    it_behaves_like 'a finalized externally signed token', 'PS512', :rsa_key, %i[base64url]
    it_behaves_like 'a finalized externally signed token', 'ES256', :ec256_key, %i[raw base64 base64url]
    it_behaves_like 'a finalized externally signed token', 'ES256K', :ec256k_key, %i[raw base64 base64url]
    it_behaves_like 'a finalized externally signed token', 'ES384', :ec384_key, %i[raw base64 base64url]
    it_behaves_like 'a finalized externally signed token', 'ES512', :ec512_key, %i[raw base64 base64url]

    it 'accepts raw R || S ECDSA signatures as well as DER ones' do
      request = described_class.prepare(payload: payload, algorithm: 'ES256')

      der_signer = SpecSupport::ExternalSigner.new(private_key: ec256_key, encoding: :raw, ecdsa_format: :der)
      raw_signer = SpecSupport::ExternalSigner.new(private_key: ec256_key, encoding: :raw, ecdsa_format: :raw)

      der_token = finalized_token(request, signature: der_signer.sign(request), key: ec256_key)
      raw_token = finalized_token(request, signature: raw_signer.sign(request), key: ec256_key)

      expect(JWT::EncodedToken.new(der_token.jwt).valid_signature?(algorithm: 'ES256', key: ec256_key)).to be(true)
      expect(JWT::EncodedToken.new(raw_token.jwt).valid_signature?(algorithm: 'ES256', key: ec256_key)).to be(true)
    end

    it 'accepts a SigningRequest object directly' do
      request = described_class.prepare(payload: payload, algorithm: 'PS256')
      signer = SpecSupport::ExternalSigner.new(private_key: rsa_key, encoding: :raw)

      token = described_class.finalize(request, signature: signer.sign(request), public_key: rsa_key)
      expect(token).to be_a(JWT::Token)
    end

    it 'produces a token that JWT.decode can verify like any other JWT' do
      request = described_class.prepare(payload: payload, algorithm: 'PS256', headers: headers)
      signer = SpecSupport::ExternalSigner.new(private_key: rsa_key)

      token = described_class.finalize(request.to_json, signature: signer.sign(request.to_json), public_key: rsa_public)
      decoded_payload, decoded_header = JWT.decode(token.jwt, rsa_public, true, algorithm: 'PS256')

      expect(decoded_payload).to eq(payload)
      expect(decoded_header).to eq('alg' => 'PS256', 'kid' => 'hsm-key-1')
    end

    it 'finalizes from JSON produced by an isolated system and verifies with a separate public key' do
      request = described_class.prepare(payload: payload, algorithm: 'ES256')
      wire = request.to_json

      signer = SpecSupport::ExternalSigner.new(private_key: ec256_key, encoding: :base64, ecdsa_format: :der)
      signature = signer.sign(wire)

      token = described_class.finalize(wire, signature: signature, public_key: ec256_public)
      expect(JWT::EncodedToken.new(token.jwt).valid_signature?(algorithm: 'ES256', key: ec256_public)).to be(true)
    end

    it 'accepts a Hash request' do
      request = described_class.prepare(payload: payload, algorithm: 'PS256')
      signer = SpecSupport::ExternalSigner.new(private_key: rsa_key, encoding: :raw)

      token = described_class.finalize(request.to_h, signature: signer.sign(request), public_key: rsa_key)
      expect(JWT::EncodedToken.new(token.jwt).valid_signature?(algorithm: 'PS256', key: rsa_key)).to be(true)
    end

    it 'accepts an RSA JWK as the verification key' do
      jwk = JWT::JWK::RSA.new(rsa_public, alg: 'PS256')
      request = described_class.prepare(payload: payload, algorithm: 'PS256')
      signer = SpecSupport::ExternalSigner.new(private_key: rsa_key)

      token = described_class.finalize(request, signature: signer.sign(request), public_key: jwk)
      expect(JWT::EncodedToken.new(token.jwt).valid_signature?(algorithm: 'PS256', key: jwk)).to be(true)
    end

    it 'accepts an EC JWK as the verification key' do
      jwk = JWT::JWK::EC.new(ec256_public, alg: 'ES256')
      request = described_class.prepare(payload: payload, algorithm: 'ES256')
      signer = SpecSupport::ExternalSigner.new(private_key: ec256_key)

      token = described_class.finalize(request, signature: signer.sign(request), public_key: jwk)
      expect(JWT::EncodedToken.new(token.jwt).valid_signature?(algorithm: 'ES256', key: jwk)).to be(true)
    end

    it 'rejects a signature made with the wrong key' do
      request = described_class.prepare(payload: payload, algorithm: 'PS256')
      signer = SpecSupport::ExternalSigner.new(private_key: rsa_key)

      expect do
        described_class.finalize(request, signature: signer.sign(request), public_key: other_rsa_public)
      end.to raise_error(JWT::VerificationError, 'Signature verification failed')
    end

    it 'rejects a signature over a different signing request' do
      request = described_class.prepare(payload: payload, algorithm: 'PS256')
      other_request = described_class.prepare(payload: { 'data' => 'something-else' }, algorithm: 'PS256')
      signer = SpecSupport::ExternalSigner.new(private_key: rsa_key)

      expect do
        request.finalize(signature: signer.sign(other_request), public_key: rsa_public)
      end.to raise_error(JWT::VerificationError, 'Signature verification failed')
    end

    it 'rejects a signature produced with a different algorithm' do
      request = described_class.prepare(payload: payload, algorithm: 'PS256')
      rs_request = described_class.prepare(payload: payload, algorithm: 'RS256',
                                           headers: { 'kid' => 'different' })
      signer = SpecSupport::ExternalSigner.new(private_key: rsa_key)

      expect do
        request.finalize(signature: signer.sign(rs_request), public_key: rsa_public)
      end.to raise_error(JWT::VerificationError, 'Signature verification failed')
    end

    it 'rejects a malformed signature' do
      request = described_class.prepare(payload: payload, algorithm: 'PS256')
      expect { request.finalize(signature: 'not-a-signature', public_key: rsa_public) }
        .to raise_error(JWT::VerificationError, 'Signature verification failed')
    end

    it 'rejects an empty signature' do
      request = described_class.prepare(payload: payload, algorithm: 'PS256')
      expect { request.finalize(signature: '', public_key: rsa_public) }
        .to raise_error(JWT::VerificationError, /non empty String/)
    end

    it 'rejects a non String signature' do
      request = described_class.prepare(payload: payload, algorithm: 'PS256')
      expect { request.finalize(signature: nil, public_key: rsa_public) }
        .to raise_error(JWT::VerificationError, /non empty String/)
    end

    it 'rejects a verification key of the wrong type' do
      request = described_class.prepare(payload: payload, algorithm: 'ES256')
      signer = SpecSupport::ExternalSigner.new(private_key: ec256_key)

      expect { request.finalize(signature: signer.sign(request), public_key: rsa_public) }
        .to raise_error(JWT::VerificationKeyError, /OpenSSL::PKey::EC/)
    end

    it 'raises on an unsupported request argument' do
      expect { described_class.finalize(123, signature: 'x', public_key: rsa_public) }
        .to raise_error(ArgumentError, /SigningRequest, Hash or JSON String/)
    end
  end

  describe 'JWT::Token integration' do
    let(:token) { JWT::Token.new(payload: payload, header: headers) }

    it 'prepares and finalizes a token in two phases' do
      request = token.prepare_signing(algorithm: 'PS256')

      signer = SpecSupport::ExternalSigner.new(private_key: rsa_key, encoding: :base64)
      token.finalize_signing!(request, signature: signer.sign(request), public_key: rsa_public)

      encoded = JWT::EncodedToken.new(token.jwt)
      expect(encoded.valid_signature?(algorithm: 'PS256', key: rsa_public)).to be(true)
      expect(encoded.header).to eq('alg' => 'PS256', 'kid' => 'hsm-key-1')
    end

    it 'rejects finalizing with a request from another token' do
      request = token.prepare_signing(algorithm: 'ES256')
      other_token = JWT::Token.new(payload: { 'data' => 'different' })
      signer = SpecSupport::ExternalSigner.new(private_key: ec256_key)

      expect do
        other_token.finalize_signing!(request, signature: signer.sign(request), public_key: ec256_public)
      end.to raise_error(JWT::VerificationError, /does not match the token/)
    end

    it 'cannot prepare an already signed token' do
      request = token.prepare_signing(algorithm: 'PS256')
      signer = SpecSupport::ExternalSigner.new(private_key: rsa_key)
      token.finalize_signing!(request, signature: signer.sign(request), public_key: rsa_public)

      expect { token.prepare_signing(algorithm: 'PS256') }
        .to raise_error(JWT::EncodeError, 'Token already signed')
    end

    it 'cannot finalize an already signed token' do
      request = token.prepare_signing(algorithm: 'PS256')
      signer = SpecSupport::ExternalSigner.new(private_key: rsa_key)
      token.finalize_signing!(request, signature: signer.sign(request), public_key: rsa_public)

      expect do
        token.finalize_signing!(request, signature: 'sig', public_key: rsa_public)
      end.to raise_error(JWT::EncodeError, 'Token already signed')
    end
  end
end
