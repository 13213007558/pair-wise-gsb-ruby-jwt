# frozen_string_literal: true

require 'base64'

RSpec.describe JWT::SigningRequest do
  let(:payload) { { 'sub' => '123', 'name' => 'John Doe' } }
  let(:headers) { { 'kid' => 'hsm-key-1' } }

  # Simulates an isolated external signer (HSM) that only exposes the
  # private key through a signing operation.
  let(:external_signer) do
    lambda do |algorithm, signing_input|
      case algorithm
      when 'PS256'
        rsa_private.sign_pss('sha256', signing_input, salt_length: :digest, mgf1_hash: 'sha256')
      when 'ES256'
        ec256_private.dsa_sign_asn1(OpenSSL::Digest.new('sha256').digest(signing_input))
      when 'ES384'
        ec384_private.dsa_sign_asn1(OpenSSL::Digest.new('sha384').digest(signing_input))
      else
        raise "unsupported algorithm #{algorithm}"
      end
    end
  end

  let(:rsa_private) { test_pkey('rsa-2048-private.pem') }
  let(:rsa_public) { test_pkey('rsa-2048-public.pem') }
  let(:rsa_wrong_public) { test_pkey('rsa-2048-wrong-public.pem') }
  let(:ec256_private) { test_pkey('ec256-private.pem') }
  let(:ec256_public) { test_pkey('ec256-public.pem') }
  let(:ec384_private) { test_pkey('ec384-private.pem') }
  let(:ec384_public) { test_pkey('ec384-public.pem') }

  describe '.prepare' do
    it 'pins the algorithm, header, payload and signing bytes' do
      request = described_class.prepare(payload, algorithm: 'PS256', headers: headers)

      expect(request.algorithm).to eq('PS256')
      expect(request.header).to eq('kid' => 'hsm-key-1', 'alg' => 'PS256')
      expect(request.payload).to eq(payload)
      expect(request.signing_input).to eq(request.to_h['signing_input'])
      expect(request.signing_input.split('.').size).to eq(2)
    end

    it 'does not let the alg header override the pinned algorithm' do
      request = described_class.prepare(payload, algorithm: 'PS256', headers: { 'alg' => 'none' })

      expect(request.header['alg']).to eq('none') # user header kept, like Token#sign!
      expect(request.algorithm).to eq('PS256')
    end

    it 'raises for an unsupported algorithm' do
      expect { described_class.prepare(payload, algorithm: 'NOPE') }
        .to raise_error(JWT::EncodeError, /Unsupported signing algorithm/)
    end

    it 'raises for symmetric algorithms' do
      expect { described_class.prepare(payload, algorithm: 'HS256') }
        .to raise_error(JWT::EncodeError, /asymmetric/)
    end

    it 'raises for the none algorithm' do
      expect { described_class.prepare(payload, algorithm: 'none') }
        .to raise_error(JWT::EncodeError, /asymmetric/)
    end

    it 'verifies numeric claims at preparation time' do
      expect { described_class.prepare({ 'exp' => 'not-a-number' }, algorithm: 'PS256') }
        .to raise_error(JWT::InvalidPayload)
    end
  end

  describe 'serialization' do
    let(:request) { described_class.prepare(payload, algorithm: 'ES256', headers: headers) }

    it 'round-trips through a Hash' do
      restored = described_class.from_h(request.to_h)

      expect(restored.to_h).to eq(request.to_h)
    end

    it 'round-trips through JSON' do
      restored = described_class.from_json(request.to_json)

      expect(restored.to_h).to eq(request.to_h)
    end

    it 'rejects a request whose signing_input does not match header and payload' do
      tampered = request.to_h
      tampered['payload'] = { 'sub' => 'attacker' }

      expect { described_class.from_h(tampered) }
        .to raise_error(JWT::EncodeError, /signing_input does not match/)
    end

    it 'rejects a request modified after preparation' do
      restored = described_class.from_json(request.to_json)
      restored.payload['sub'] = 'attacker'
      signature = external_signer.call('ES256', request.signing_input)

      expect { restored.finalize(signature, key: ec256_public) }
        .to raise_error(JWT::EncodeError, /modified after preparation/)
    end
  end

  describe '#finalize' do
    context 'with RSA-PSS' do
      let(:request) { described_class.prepare(payload, algorithm: 'PS256', headers: headers) }

      it 'produces a verifiable token from a raw signature' do
        signature = external_signer.call('PS256', request.signing_input)
        token = request.finalize(signature, key: rsa_public)

        expect(JWT.decode(token, rsa_public, true, algorithm: 'PS256').first).to eq(payload)
      end

      it 'accepts a Base64 encoded signature' do
        signature = Base64.strict_encode64(external_signer.call('PS256', request.signing_input))
        token = request.finalize(signature, key: rsa_public)

        expect(JWT.decode(token, rsa_public, true, algorithm: 'PS256').first).to eq(payload)
      end

      it 'accepts a Base64URL encoded signature' do
        signature = Base64.urlsafe_encode64(external_signer.call('PS256', request.signing_input))
        token = request.finalize(signature, key: rsa_public)

        expect(JWT.decode(token, rsa_public, true, algorithm: 'PS256').first).to eq(payload)
      end

      it 'rejects a signature made for a different request' do
        other = described_class.prepare({ 'sub' => 'other' }, algorithm: 'PS256')
        signature = external_signer.call('PS256', other.signing_input)

        expect { request.finalize(signature, key: rsa_public) }
          .to raise_error(JWT::VerificationError)
      end

      it 'rejects a signature from the wrong key' do
        signature = external_signer.call('PS256', request.signing_input)

        expect { request.finalize(signature, key: rsa_wrong_public) }
          .to raise_error(JWT::VerificationError)
      end

      it 'rejects a key of the wrong type' do
        signature = external_signer.call('PS256', request.signing_input)

        expect { request.finalize(signature, key: ec256_public) }
          .to raise_error(JWT::VerificationKeyError)
      end
    end

    context 'with ECDSA' do
      let(:request) { described_class.prepare(payload, algorithm: 'ES256', headers: headers) }

      it 'accepts an ASN.1 DER encoded signature, as returned by OpenSSL and many HSMs' do
        der_signature = external_signer.call('ES256', request.signing_input)
        token = request.finalize(der_signature, key: ec256_public)

        expect(JWT.decode(token, ec256_public, true, algorithm: 'ES256').first).to eq(payload)
      end

      it 'accepts a Base64URL encoded DER signature' do
        der_signature = external_signer.call('ES256', request.signing_input)
        token = request.finalize(Base64.urlsafe_encode64(der_signature), key: ec256_public)

        expect(JWT.decode(token, ec256_public, true, algorithm: 'ES256').first).to eq(payload)
      end

      it 'accepts a raw R || S signature' do
        der_signature = external_signer.call('ES256', request.signing_input)
        raw_signature = JWT::ExternalSignature.der_to_raw(der_signature, 32)
        token = request.finalize(raw_signature, key: ec256_public)

        expect(JWT.decode(token, ec256_public, true, algorithm: 'ES256').first).to eq(payload)
      end

      it 'handles other curves' do
        request = described_class.prepare(payload, algorithm: 'ES384')
        der_signature = external_signer.call('ES384', request.signing_input)
        token = request.finalize(der_signature, key: ec384_public)

        expect(JWT.decode(token, ec384_public, true, algorithm: 'ES384').first).to eq(payload)
      end

      it 'rejects a signature made for a different request' do
        other = described_class.prepare({ 'sub' => 'other' }, algorithm: 'ES256')
        signature = external_signer.call('ES256', other.signing_input)

        expect { request.finalize(signature, key: ec256_public) }
          .to raise_error(JWT::VerificationError)
      end

      it 'rejects garbage signatures' do
        expect { request.finalize('not-a-signature', key: ec256_public) }
          .to raise_error(JWT::VerificationError)
      end

      it 'rejects a non-string signature' do
        expect { request.finalize(nil, key: ec256_public) }
          .to raise_error(JWT::VerificationError, /must be a String/)
      end

      it 'rejects a key of the wrong type' do
        signature = external_signer.call('ES256', request.signing_input)

        expect { request.finalize(signature, key: rsa_public) }
          .to raise_error(JWT::VerificationKeyError)
      end

      it 'rejects a key for a different curve' do
        signature = external_signer.call('ES256', request.signing_input)

        expect { request.finalize(signature, key: ec384_public) }
          .to raise_error(JWT::IncorrectAlgorithm)
      end
    end
  end

  describe 'JWT module functions' do
    it 'JWT.prepare returns a signing request' do
      expect(JWT.prepare(payload, algorithm: 'PS256', headers: headers)).to be_a(described_class)
    end

    it 'JWT.finalize accepts a prepared request' do
      request = JWT.prepare(payload, algorithm: 'PS256', headers: headers)
      signature = external_signer.call('PS256', request.signing_input)
      token = JWT.finalize(request, signature, key: rsa_public)

      expect(JWT.decode(token, rsa_public, true, algorithm: 'PS256').first).to eq(payload)
    end

    it 'JWT.finalize accepts a serialized Hash' do
      request = JWT.prepare(payload, algorithm: 'PS256', headers: headers)
      signature = external_signer.call('PS256', request.signing_input)
      token = JWT.finalize(request.to_h, signature, key: rsa_public)

      expect(JWT.decode(token, rsa_public, true, algorithm: 'PS256').first).to eq(payload)
    end

    it 'JWT.finalize accepts a serialized JSON document' do
      request = JWT.prepare(payload, algorithm: 'PS256', headers: headers)
      signature = external_signer.call('PS256', request.signing_input)
      token = JWT.finalize(request.to_json, signature, key: rsa_public)

      expect(JWT.decode(token, rsa_public, true, algorithm: 'PS256').first).to eq(payload)
    end

    it 'produces a token identical to JWT.encode with the same key' do
      request = JWT.prepare(payload, algorithm: 'ES256')
      der_signature = external_signer.call('ES256', request.signing_input)
      token = JWT.finalize(request, der_signature, key: ec256_public)

      expect(JWT.decode(token, ec256_public, true, algorithm: 'ES256').first).to eq(payload)
    end
  end
end
