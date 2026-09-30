# frozen_string_literal: true

RSpec.describe JWT::JWS do
  let(:key_one) { 'one-signing-key-with-enough-length' }
  let(:key_two) { 'two-signing-key-with-enough-length' }
  let(:payload) { { 'sub' => 'subject', 'data' => 'payload' } }

  let(:signer_one) do
    JWT::JWS::Signer.new(algorithm: 'HS256', key: key_one, protected_header: { 'kid' => 'one' })
  end
  let(:signer_two) do
    JWT::JWS::Signer.new(algorithm: 'HS256', key: key_two, header: { 'kid' => 'two' })
  end

  describe '.general_serialize' do
    subject(:general) { described_class.general_serialize(payload, [signer_one, signer_two]) }

    it 'contains the shared payload and every signature' do
      expect(general).to include('payload', 'signatures')
      expect(general['signatures'].size).to eq(2)
    end

    it 'carries protected and unprotected headers separately' do
      expect(general['signatures'][0]).to include('protected', 'signature')
      expect(general['signatures'][0]).not_to include('header')
      expect(general['signatures'][1]['header']).to eq('kid' => 'two')
    end

    it 'signs each signature over the same payload' do
      general['signatures'].each_with_index do |entry, index|
        compact = [entry['protected'], general['payload'], entry['signature']].join('.')
        token = JWT::EncodedToken.new(compact)
        expect(token.valid_signature?(algorithm: 'HS256', key: index.zero? ? key_one : key_two)).to be(true)
      end
    end

    it 'accepts signers given as hashes' do
      built = described_class.general_serialize(payload, [
        { algorithm: 'HS256', key: key_one },
        { algorithm: 'HS256', key: key_two }
      ])

      expect(built['signatures'].size).to eq(2)
    end

    context 'without signers' do
      it 'raises an encoding error' do
        expect { described_class.general_serialize(payload, []) }.to raise_error(JWT::EncodeError, /at least one signer/)
      end
    end
  end

  describe '.flattened_serialize' do
    subject(:flattened) { described_class.flattened_serialize(payload, signer_one) }

    it 'places the signature members at the top level' do
      expect(flattened).to include('payload', 'protected', 'signature')
      expect(flattened).not_to include('signatures')
    end

    it 'round trips through decode' do
      result = described_class.decode(flattened, algorithms: ['HS256'], key: key_one)

      expect(result).to be_verified
      expect(result.verified_payload).to eq(payload)
    end
  end

  describe '.decode' do
    let(:general) { described_class.general_serialize(payload, [signer_one, signer_two]) }
    let(:json) { JWT::JSON.generate(general) }

    subject(:result) { described_class.decode(json, algorithms: ['HS256'], key: [key_one, key_two]) }

    it 'verifies both signatures and returns the payload' do
      expect(result.signature_results).to all(be_valid)
      expect(result).to be_verified
      expect(result.verified_payload).to eq(payload)
    end

    it 'exposes each signature and merged headers in the results' do
      expect(result.signature_results[0].header['kid']).to eq('one')
      expect(result.signature_results[1].header['kid']).to eq('two')
    end

    it 'accepts the serialization as a hash' do
      expect(described_class.decode(general, algorithms: ['HS256'], key: [key_one, key_two])).to be_verified
    end

    it 'exposes the unverified payload regardless of verification' do
      expect(result.payload).to eq(payload)
    end

    it 'returns the verified payload through decode!' do
      expect(described_class.decode!(json, algorithms: ['HS256'], key: [key_one, key_two])).to eq(payload)
    end

    it 'raises through decode! when the policy is not met' do
      general['signatures'][1]['signature'] = JWT::Base64.url_encode('bad-signature-value!')

      expect { described_class.decode!(json, algorithms: ['HS256'], key: [key_one, key_two]) }
        .to raise_error(JWT::VerificationError)
    end

    context 'with a fixed key set' do
      context 'when a protected header is moved to another signature' do
        before do
          entries = general['signatures']
          entries[0]['protected'], entries[1]['protected'] = entries[1]['protected'], entries[0]['protected']
        end

        it 'reports every signature as invalid and does not verify' do
          expect(result.signature_results).not_to include(be_valid)
          expect(result).not_to be_verified
        end

        it 'does not return verified claims' do
          expect { result.verified_payload }.to raise_error(JWT::VerificationError, /policy not satisfied/)
        end
      end

      context 'when a signature is missing' do
        before { general['signatures'][0].delete('signature') }

        it 'reports the missing signature as invalid but the sibling as valid' do
          expect(result.signature_results[0]).not_to be_valid
          expect(result.signature_results[0].error).to be_a(JWT::MalformedTokenError)
          expect(result.signature_results[1]).to be_valid
        end

        it 'does not verify the token or return claims' do
          expect(result).not_to be_verified
          expect { result.verified_payload }.to raise_error(JWT::VerificationError)
        end
      end

      context 'when one signature is tampered while the other stays valid' do
        before do
          general['signatures'][1]['signature'] = JWT::Base64.url_encode('tampered-signature-value!')
        end

        it 'does not let the valid signature mask the invalid one' do
          expect(result.signature_results[0]).to be_valid
          expect(result.signature_results[1]).not_to be_valid
          expect(result).not_to be_verified
        end

        it 'keeps the claims unavailable' do
          expect { result.verified_payload }.to raise_error(JWT::VerificationError)
        end
      end

      context 'when the same key signed twice' do
        let(:general) do
          described_class.general_serialize(payload, [
            JWT::JWS::Signer.new(algorithm: 'HS256', key: key_one, protected_header: { 'kid' => 'one' }),
            JWT::JWS::Signer.new(algorithm: 'HS256', key: key_one, header: { 'kid' => 'two' })
          ])
        end

        it 'does not count the key as two independent signers' do
          expect(result.signature_results).to all(be_valid)
          expect(result).not_to be_verified
        end
      end
    end

    context 'with duplicate protected and unprotected headers' do
      let(:general) do
        described_class.general_serialize(payload, [
          JWT::JWS::Signer.new(algorithm: 'HS256', key: key_one,
                                protected_header: { 'kid' => 'one', 'crit' => ['kid'] })
        ])
      end

      before do
        general['signatures'][0]['header'] = { 'kid' => 'one' }
      end

      it 'rejects the signature' do
        expect(result.signature_results[0]).not_to be_valid
        expect(result.signature_results[0].error.message).to include('both protected and unprotected')
      end
    end

    context 'with the algorithm whitelist' do
      subject(:result) { described_class.decode(json, algorithms: ['RS256'], key: [key_one, key_two]) }

      it 'rejects signatures with non whitelisted algorithms' do
        expect(result).not_to be_verified
        expect(result.signature_results[0].error).to be_a(JWT::IncorrectAlgorithm)
      end
    end

    context 'without any allowed algorithm' do
      it 'raises before verification' do
        expect { described_class.decode(json, algorithms: [], key: key_one) }
          .to raise_error(JWT::IncorrectAlgorithm, 'An algorithm must be specified')
      end
    end

    context 'with critical headers' do
      let(:general) do
        described_class.general_serialize(payload, [
          JWT::JWS::Signer.new(algorithm: 'HS256', key: key_one,
                                protected_header: { 'crit' => ['http://example.com/unknown'],
                                                    'http://example.com/unknown' => true })
        ])
      end

      context 'when the caller does not understand the crit parameter' do
        it 'does not ignore the unknown parameter' do
          expect(result.signature_results[0].error).to be_a(JWT::InvalidCritError)
          expect(result).not_to be_verified
        end
      end

      context 'when crit is placed in the unprotected header' do
        let(:general) do
          payload_b64 = JWT::Base64.url_encode(JWT::JSON.generate(payload))
          protected_b64 = JWT::Base64.url_encode(JWT::JSON.generate('alg' => 'HS256'))
          {
            'payload' => payload_b64,
            'signatures' => [{
              'protected' => protected_b64,
              'header' => { 'crit' => ['kid'] },
              'signature' => 'whatever'
            }]
          }
        end

        it 'rejects the signature with a crit error' do
          expect(result.signature_results[0].error).to be_a(JWT::InvalidCritError)
          expect(result).not_to be_verified
        end
      end

      context 'when the caller declares the crit parameter as understood' do
        subject(:result) do
          described_class.decode(json, algorithms: ['HS256'], key: key_one,
                                                    critical_headers: ['http://example.com/unknown'])
        end

        it 'verifies the signature' do
          expect(result).to be_verified
        end
      end

      context 'when crit references a registered understood parameter' do
        let(:general) do
          described_class.general_serialize(payload, [
            JWT::JWS::Signer.new(algorithm: 'HS256', key: key_one,
                                  protected_header: { 'crit' => ['kid'], 'kid' => 'one' })
          ])
        end

        it 'accepts valid registered crit values' do
          expect(result).to be_verified
        end
      end
    end

    context 'with a threshold policy' do
      subject(:result) do
        described_class.decode(json, algorithms: ['HS256'], key: [key_one, key_two], policy: policy)
      end

      context 'of one distinct signer' do
        let(:policy) { 1 }

        it 'verifies already with one signature' do
          expect(result).to be_verified
        end
      end

      context 'given as a hash' do
        let(:policy) { { minimum: 2 } }

        it 'requires two distinct signers' do
          expect(result).to be_verified
        end
      end

      context 'that cannot be reached with the keys' do
        let(:policy) { 3 }

        it 'reports the missing signers and keeps the payload unverified' do
          expect(result).not_to be_verified
          expect { result.verified_payload }.to raise_error(JWT::VerificationError, /3 distinct/)
        end
      end
    end

    context 'with a key finder block' do
      subject(:result) do
        described_class.decode(json, algorithms: ['HS256'], policy: 2) do |headers, _payload|
          headers['kid'] == 'one' ? key_one : key_two
        end
      end

      it 'resolves the key independently for every signature' do
        expect(result.signature_results).to all(be_valid)
        expect(result).to be_verified
      end
    end

    context 'with claim verification' do
      let(:payload) { { 'sub' => 'subject', 'exp' => Time.now.to_i - 100 } }

      it 'verifies the claims once the signature policy passes' do
        expect(result).not_to be_verified
        expect(result.claims_error).to be_a(JWT::ExpiredSignature)
      end

      it 'raises the claim error when accessing the verified payload' do
        expect { result.verified_payload }.to raise_error(JWT::ExpiredSignature)
      end

      context 'when the policy already fails' do
        before { general['signatures'][1]['signature'] = JWT::Base64.url_encode('bad') }

        it 'reports the signature failure rather than claims' do
          expect(result).not_to be_verified
          expect { result.verified_payload }.to raise_error(JWT::VerificationError)
        end
      end
    end

    context 'with malformed serializations' do
      it 'raises for invalid JSON' do
        expect { described_class.decode('not-json', algorithms: ['HS256'], key: key_one) }
          .to raise_error(JWT::MalformedTokenError, 'Invalid JWS JSON serialization')
      end

      it 'raises when the payload is missing' do
        expect { described_class.decode({ 'signature' => 'x' }, algorithms: ['HS256'], key: key_one) }
          .to raise_error(JWT::MalformedTokenError, /payload/)
      end

      it 'raises when no signature is present' do
        expect { described_class.decode({ 'payload' => 'x' }, algorithms: ['HS256'], key: key_one) }
          .to raise_error(JWT::MalformedTokenError, /any signature/)
      end

      it 'raises when general and flattened members are mixed' do
        mixed = general.merge('signature' => 'x')
        expect { described_class.decode(mixed, algorithms: ['HS256'], key: key_one) }
          .to raise_error(JWT::MalformedTokenError, /must not be mixed/)
      end
    end

    context 'with RSA keys' do
      let(:private_key) { test_pkey('rsa-2048-private.pem') }
      let(:public_key) { test_pkey('rsa-2048-public.pem') }

      let(:general) do
        described_class.general_serialize(payload, [
          JWT::JWS::Signer.new(algorithm: 'RS256', key: private_key)
        ])
      end

      subject(:result) { described_class.decode(general, algorithms: ['RS256'], key: public_key) }

      it 'verifies asymmetric signatures' do
        expect(result).to be_verified
        expect(result.verified_payload).to eq(payload)
      end
    end

    context 'with a JWK key' do
      let(:rsa_key) { OpenSSL::PKey::RSA.new(2048) }
      let(:jwk) { JWT::JWK::RSA.new(rsa_key, alg: 'RS256', kid: 'json-signer') }

      let(:general) do
        described_class.general_serialize(payload, [
          JWT::JWS::Signer.new(algorithm: 'RS256', key: jwk, protected_header: { 'kid' => jwk.kid })
        ])
      end

      subject(:result) { described_class.decode(general, algorithms: ['RS256'], key: [jwk]) }

      it 'verifies with the JWK and reports its identity' do
        expect(result).to be_verified
        expect(result.signature_results.first.key_identity).to eq('jwk:json-signer')
      end
    end

    context 'with the none algorithm' do
      let(:general) do
        described_class.general_serialize(payload, [JWT::JWS::Signer.new(algorithm: 'none', key: nil)])
      end

      subject(:result) { described_class.decode(general, algorithms: ['none']) }

      it 'verifies an empty signature without a key' do
        expect(result).to be_verified
        expect(result.verified_payload).to eq(payload)
      end

      context 'when the signature is not empty' do
        before { general['signatures'][0]['signature'] = JWT::Base64.url_encode('not-empty') }

        it 'rejects the signature' do
          expect(result).not_to be_verified
          expect(result.signature_results[0].error).to be_a(JWT::VerificationError)
        end
      end
    end
  end
end
