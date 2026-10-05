# frozen_string_literal: true

RSpec.describe JWT do
  describe '.decode with JWE' do
    let(:direct_key) { "\0" * 16 }
    let(:direct_vector) do
      'eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..AAAAAAAAAAAAAAAA.eKqvvA6MxuqSRbLVFIidFJb8x4lzPytWkoA.aglYAurAaFCoM8sCqaXSyw'
    end

    it 'requires an explicit key management allowlist' do
      expect { described_class.decode(direct_vector, direct_key) }
        .to raise_error(JWT::IncorrectAlgorithm, 'A JWE key management algorithm must be specified')
    end

    it 'requires an explicit content encryption allowlist' do
      expect do
        described_class.decode(direct_vector, direct_key, true, jwe_algorithms: ['dir'], verify_expiration: false)
      end.to raise_error(JWT::IncorrectAlgorithm, 'A JWE content encryption algorithm must be specified')
    end

    it 'decrypts direct claims without using the JWS algorithm allowlist' do
      payload, header = described_class.decode(
        direct_vector,
        direct_key,
        true,
        jwe_algorithms: ['dir'],
        jwe_encryption_algorithms: ['A128GCM'],
        algorithms: ['RS256'],
        verify_expiration: false
      )

      expect(payload).to eq('urn:example:claim' => true)
      expect(header).to eq('alg' => 'dir', 'enc' => 'A128GCM')
    end

    context 'with a nested JWS' do
      let(:signing_key) { 'jws-secret' }
      let(:payload) { { 'data' => 'protected', 'exp' => Time.now.to_i + 300 } }
      let(:nested_jws) { described_class.encode(payload, signing_key, 'HS256') }
      let(:encrypted) do
        described_class::JWE::CompactToken.encrypt(
          nested_jws,
          key: direct_key,
          algorithm: 'dir',
          encryption_algorithm: 'A128GCM',
          cty: 'jwt'
        )
      end

      it 'requires an independent JWS algorithm policy' do
        expect do
          described_class.decode(encrypted, direct_key, true,
                                 jwe_algorithms: ['dir'],
                                 jwe_encryption_algorithms: ['A128GCM'])
        end.to raise_error(JWT::IncorrectAlgorithm, 'An independent JWS algorithm must be specified for nested tokens')
      end

      it 'decrypts first and then verifies the inner JWS policy' do
        payload_result, inner_header, outer_header = described_class.decode(
          encrypted,
          direct_key,
          true,
          jwe_algorithms: ['dir'],
          jwe_encryption_algorithms: ['A128GCM'],
          nested_signature: { algorithms: ['HS256'], key: signing_key }
        )

        expect(payload_result).to eq(payload)
        expect(inner_header).to include('alg' => 'HS256')
        expect(outer_header).to include('alg' => 'dir', 'enc' => 'A128GCM', 'cty' => 'jwt')
      end

      it 'does not let outer cty choose or relax the inner signature algorithm' do
        unsigned_nested = described_class.encode(payload, nil, 'none')
        tampered = described_class::JWE::CompactToken.encrypt(
          unsigned_nested,
          key: direct_key,
          algorithm: 'dir',
          encryption_algorithm: 'A128GCM',
          cty: 'JWT'
        )

        expect do
          described_class.decode(tampered, direct_key, true,
                                 jwe_algorithms: ['dir'],
                                 jwe_encryption_algorithms: ['A128GCM'],
                                 nested_signature: { algorithms: ['HS256'], key: signing_key })
        end.to raise_error(JWT::IncorrectAlgorithm)
      end

      it 'rejects an inner signature algorithm outside the explicit policy' do
        expect do
          described_class.decode(encrypted, direct_key, true,
                                 jwe_algorithms: ['dir'],
                                 jwe_encryption_algorithms: ['A128GCM'],
                                 nested_signature: { algorithms: ['RS256'], key: signing_key })
        end.to raise_error(JWT::IncorrectAlgorithm)
      end
    end
  end
end
