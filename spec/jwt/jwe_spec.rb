# frozen_string_literal: true

RSpec.describe JWT::JWE do
  let(:cek128) { ('a'..'p').to_a.join }
  let(:cek256) { ('a'..'z').to_a.join + '012345' }
  let(:payload) { { 'sub' => 'alice', 'admin' => true } }
  let(:rsa_key) { test_pkey('rsa-2048-private.pem') }
  let(:rsa_public) { test_pkey('rsa-2048-public.pem') }

  def tamper_segment(token, index)
    segments = token.split('.')
    segment = segments[index]
    replacement = segment[0] == 'A' ? 'B' : 'A'
    segments[index] = segment.empty? ? 'AA' : replacement + segment[1..-1]
    segments.join('.')
  end

  describe '.encrypt and .decrypt' do
    it 'round-trips a payload with dir and A128GCM' do
      token = described_class.encrypt(payload, cek128, algorithm: 'dir', encryption: 'A128GCM')
      expect(token.split('.').size).to eq(5)

      decrypted, header = described_class.decrypt(token, cek128, algorithms: ['dir'], encryptions: ['A128GCM'])
      expect(decrypted).to eq(payload)
      expect(header).to eq('alg' => 'dir', 'enc' => 'A128GCM')
    end

    it 'round-trips a payload with dir and A256GCM' do
      token = described_class.encrypt(payload, cek256, algorithm: 'dir', encryption: 'A256GCM')
      decrypted, = described_class.decrypt(token, cek256, algorithms: ['dir'], encryptions: ['A256GCM'])
      expect(decrypted).to eq(payload)
    end

    it 'leaves the encrypted key segment empty for dir' do
      token = described_class.encrypt(payload, cek128, algorithm: 'dir', encryption: 'A128GCM')
      expect(token.split('.')[1]).to eq('')
    end

    it 'round-trips a payload with RSA-OAEP-256 and A128GCM' do
      token = described_class.encrypt(payload, rsa_public, algorithm: 'RSA-OAEP-256', encryption: 'A128GCM')
      decrypted, = described_class.decrypt(token, rsa_key, algorithms: ['RSA-OAEP-256'], encryptions: ['A128GCM'])
      expect(decrypted).to eq(payload)
    end

    it 'round-trips a payload with RSA-OAEP-256 and A256GCM' do
      token = described_class.encrypt(payload, rsa_public, algorithm: 'RSA-OAEP-256', encryption: 'A256GCM')
      decrypted, = described_class.decrypt(token, rsa_key, algorithms: ['RSA-OAEP-256'], encryptions: ['A256GCM'])
      expect(decrypted).to eq(payload)
    end

    it 'does not let additional headers override alg and enc' do
      token = described_class.encrypt(payload, cek256, algorithm: 'dir', encryption: 'A256GCM',
                                      headers: { 'alg' => 'RSA-OAEP-256', 'enc' => 'A128GCM', 'kid' => 'key-1' })
      header = JWT::JSON.parse(JWT::Base64.url_decode(token.split('.').first))
      expect(header).to eq('alg' => 'dir', 'enc' => 'A256GCM', 'kid' => 'key-1')
    end

    it 'raises JWEError for an unsupported key management algorithm' do
      expect { described_class.encrypt(payload, cek128, algorithm: 'A128KW', encryption: 'A128GCM') }
        .to raise_error(JWT::JWEError, 'Unsupported alg algorithm: A128KW')
    end

    it 'raises JWEError for an unsupported content encryption algorithm' do
      expect { described_class.encrypt(payload, cek128, algorithm: 'dir', encryption: 'A128CBC-HS256') }
        .to raise_error(JWT::JWEError, 'Unsupported enc algorithm: A128CBC-HS256')
    end

    it 'raises JWEError when the dir key does not match the CEK length' do
      expect { described_class.encrypt(payload, cek128, algorithm: 'dir', encryption: 'A256GCM') }
        .to raise_error(JWT::JWEError, /256-bit CEK/)
    end

    it 'raises JWEError when RSA-OAEP-256 is used with a non-RSA key' do
      expect { described_class.encrypt(payload, cek128, algorithm: 'RSA-OAEP-256', encryption: 'A128GCM') }
        .to raise_error(JWT::JWEError, /OpenSSL::PKey::RSA/)
    end
  end

  describe 'public standard vectors' do
    # AES-GCM test vectors from "The Galois/Counter Mode of Operation (GCM)"
    # (McGrew & Viega), also used in the NIST CAVP GCM test suite.
    describe 'NIST AES-GCM vectors' do
      def hex(str)
        [str].pack('H*')
      end

      it 'decrypts the AES-128 zero vector' do
        gcm = JWT::JWE::ContentEncryption.find('A128GCM')
        plaintext = gcm.decrypt(cek: hex('00' * 16), iv: hex('00' * 12),
                                ciphertext: hex('0388dace60b6a392f328c2b971b2fe78'),
                                tag: hex('ab6e47d42cec13bdf53a67b21257bddf'), aad: '')
        expect(plaintext).to eq(hex('00' * 16))
      end

      it 'decrypts the AES-256 zero vector' do
        gcm = JWT::JWE::ContentEncryption.find('A256GCM')
        plaintext = gcm.decrypt(cek: hex('00' * 32), iv: hex('00' * 12),
                                ciphertext: hex('cea7403d4d606b6e074ec5d3baf39d18'),
                                tag: hex('d0d1c8a799996bf0265b98b5d48ab919'), aad: '')
        expect(plaintext).to eq(hex('00' * 16))
      end

      it 'verifies the AES-128 empty plaintext vector' do
        gcm = JWT::JWE::ContentEncryption.find('A128GCM')
        plaintext = gcm.decrypt(cek: hex('00' * 16), iv: hex('00' * 12),
                                ciphertext: '',
                                tag: hex('58e2fccefa7e3061367f1d57a4e7455a'), aad: '')
        expect(plaintext).to eq('')
      end
    end

    # JWE compact serializations generated with an independent implementation
    # of RFC 7516 (Python cryptography), using fixed CEKs and IVs.
    describe 'JWE compact serialization vectors' do
      let(:dir_vector) do
        'eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..' \
          'oKCgoKCgoKCgoKCg.J3qzly-o5W8SxCXg9JTF_4ZlgX355_WrXlISfg.xQjG5IGegTUclvFUCrQWxw'
      end

      let(:rsa_vector) do
        'eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.' \
          'iVfUR1RZZImaaD7jvEg1uBcif2UBKxSKsekhmr6RV7HgX6zlPiBZhVZq1O5zy_5kkB_zf0ObD8ZK6YQhxy_lKO8Oaj0QfaxSavjFs6U5u7pX4rKHhaebtMoxYcnHMXrTbjk3N_QyISUQZ6QH0KzeRYU97-tw6BXekYRiCYUsa4kDPpTzf2ERsDRkHx3qMhmVOLhgKA_b4NL_W4xOjy-G4FWtR4F68AoeNC-GpmPmhPDMubbNpq3g16X_Dhx4OhEwPtouK34rbWeEVMFJpPhjFEGH4hiytqIp8uY4_3W1_R1wewl2IDN1g4PQjuXuZqCky7cqMdoqcidgIrjca6Lnew.' \
          'sLCwsLCwsLCwsLCw.gZCVOe3opIht7rvbro1FoAnxN0TE9u7gK8n0QUAoLO0R0tTchzC0M3hQ7gOqzCquDA.Xb1AS8uaiUJ7apn9AlHkBg'
      end

      it 'decrypts the dir + A128GCM vector' do
        decrypted, header = described_class.decrypt(dir_vector, (0..15).to_a.pack('C*'),
                                                    algorithms: ['dir'], encryptions: ['A128GCM'])
        expect(decrypted).to eq('sub' => 'alice', 'admin' => true)
        expect(header).to eq('alg' => 'dir', 'enc' => 'A128GCM')
      end

      it 'decrypts the RSA-OAEP-256 + A256GCM vector' do
        decrypted, header = described_class.decrypt(rsa_vector, rsa_key,
                                                    algorithms: ['RSA-OAEP-256'], encryptions: ['A256GCM'])
        expect(decrypted).to eq('iss' => 'https://issuer.example', 'exp' => 1_893_456_000)
        expect(header).to eq('alg' => 'RSA-OAEP-256', 'enc' => 'A256GCM')
      end
    end
  end

  describe 'explicit algorithm allowlists' do
    let(:token) { described_class.encrypt(payload, cek256, algorithm: 'dir', encryption: 'A256GCM') }

    it 'requires key management algorithms to be explicitly allowed' do
      expect { described_class.decrypt(token, cek256, encryptions: ['A256GCM']) }
        .to raise_error(ArgumentError, /algorithms/)
    end

    it 'requires content encryption algorithms to be explicitly allowed' do
      expect { described_class.decrypt(token, cek256, algorithms: ['dir']) }
        .to raise_error(ArgumentError, /encryptions/)
    end

    it 'rejects an empty algorithm allowlist' do
      expect { described_class.decrypt(token, cek256, algorithms: [], encryptions: ['A256GCM']) }
        .to raise_error(ArgumentError, /algorithms/)
    end

    it 'rejects a token whose alg is not allowed' do
      expect { described_class.decrypt(token, cek256, algorithms: ['RSA-OAEP-256'], encryptions: ['A256GCM']) }
        .to raise_error(JWT::JWEError, 'Token alg header is not in the allowed algorithms')
    end

    it 'rejects a token whose enc is not allowed' do
      expect { described_class.decrypt(token, cek256, algorithms: ['dir'], encryptions: ['A128GCM']) }
        .to raise_error(JWT::JWEError, 'Token enc header is not in the allowed algorithms')
    end

    it 'rejects algorithms unknown to the library even when allowed' do
      header = JWT::Base64.url_encode(JWT::JSON.generate('alg' => 'A128KW', 'enc' => 'A256GCM'))
      token = [header, '', '', '', ''].join('.')
      expect { described_class.decrypt(token, cek256, algorithms: ['A128KW'], encryptions: ['A256GCM']) }
        .to raise_error(JWT::JWEError, 'Token alg header is not in the allowed algorithms')
    end

    it 'accepts a token when alg and enc are both allowed' do
      decrypted, = described_class.decrypt(token, cek256, algorithms: %w[RSA-OAEP-256 dir], encryptions: %w[A128GCM A256GCM])
      expect(decrypted).to eq(payload)
    end
  end

  describe 'malformed tokens' do
    it 'rejects nil' do
      expect { described_class.decrypt(nil, cek128, algorithms: ['dir'], encryptions: ['A128GCM']) }
        .to raise_error(JWT::MalformedTokenError, 'Nil JSON web encryption')
    end

    it 'rejects tokens with other than five segments' do
      expect { described_class.decrypt('a.b.c.d', cek128, algorithms: ['dir'], encryptions: ['A128GCM']) }
        .to raise_error(JWT::MalformedTokenError, 'Not enough or too many segments')
      expect { described_class.decrypt('a.b.c.d.e.f', cek128, algorithms: ['dir'], encryptions: ['A128GCM']) }
        .to raise_error(JWT::MalformedTokenError, 'Not enough or too many segments')
    end

    it 'rejects a header that is not valid base64' do
      expect { described_class.decrypt('!!!.a.b.c.d', cek128, algorithms: ['dir'], encryptions: ['A128GCM']) }
        .to raise_error(JWT::Base64DecodeError)
    end

    it 'rejects a header that is not valid JSON' do
      header = JWT::Base64.url_encode('not json')
      expect { described_class.decrypt("#{header}.a.b.c.d", cek128, algorithms: ['dir'], encryptions: ['A128GCM']) }
        .to raise_error(JWT::MalformedTokenError, 'Invalid segment encoding')
    end

    it 'rejects a header that is not a JSON object' do
      header = JWT::Base64.url_encode(JWT::JSON.generate(['dir']))
      expect { described_class.decrypt("#{header}.a.b.c.d", cek128, algorithms: ['dir'], encryptions: ['A128GCM']) }
        .to raise_error(JWT::MalformedTokenError, 'Token header not a JSON object')
    end

    it 'rejects a token without an alg header' do
      header = JWT::Base64.url_encode(JWT::JSON.generate('enc' => 'A128GCM'))
      expect { described_class.decrypt("#{header}.a.b.c.d", cek128, algorithms: ['dir'], encryptions: ['A128GCM']) }
        .to raise_error(JWT::JWEError, 'Token is missing alg header')
    end

    it 'rejects a token without an enc header' do
      header = JWT::Base64.url_encode(JWT::JSON.generate('alg' => 'dir'))
      expect { described_class.decrypt("#{header}.a.b.c.d", cek128, algorithms: ['dir'], encryptions: ['A128GCM']) }
        .to raise_error(JWT::JWEError, 'Token is missing enc header')
    end

    it 'rejects tokens using zip' do
      header = JWT::Base64.url_encode(JWT::JSON.generate('alg' => 'dir', 'enc' => 'A128GCM', 'zip' => 'DEF'))
      expect { described_class.decrypt("#{header}.a.b.c.d", cek128, algorithms: ['dir'], encryptions: ['A128GCM']) }
        .to raise_error(JWT::JWEError, 'Unsupported zip header')
    end

    it 'rejects tokens with crit extensions' do
      header = JWT::Base64.url_encode(JWT::JSON.generate('alg' => 'dir', 'enc' => 'A128GCM', 'crit' => ['exp'], 'exp' => true))
      expect { described_class.decrypt("#{header}.a.b.c.d", cek128, algorithms: ['dir'], encryptions: ['A128GCM']) }
        .to raise_error(JWT::JWEError, 'Unsupported crit header')
    end

    it 'rejects a dir token carrying an encrypted key' do
      token = described_class.encrypt(payload, cek128, algorithm: 'dir', encryption: 'A128GCM')
      segments = token.split('.')
      segments[1] = JWT::Base64.url_encode('unexpected-key-material')
      expect { described_class.decrypt(segments.join('.'), cek128, algorithms: ['dir'], encryptions: ['A128GCM']) }
        .to raise_error(JWT::DecryptionError, 'JWE decryption failed')
    end

    it 'rejects a decrypted payload that is not valid JSON' do
      token = described_class.encrypt('not json at all', cek128, algorithm: 'dir', encryption: 'A128GCM')
      expect { described_class.decrypt(token, cek128, algorithms: ['dir'], encryptions: ['A128GCM']) }
        .to raise_error(JWT::MalformedTokenError, 'Invalid payload encoding')
    end
  end

  describe 'segment tampering' do
    shared_examples 'tamper resistant token' do
      it 'rejects a tampered protected header' do
        # A structurally valid header with an extra field changes the AAD.
        segments = token.split('.')
        header = JWT::JSON.parse(JWT::Base64.url_decode(segments[0])).merge('kid' => 'attacker')
        segments[0] = JWT::Base64.url_encode(JWT::JSON.generate(header))
        expect { decrypt(segments.join('.')) }.to raise_error(JWT::DecryptionError, 'JWE decryption failed')
      end

      it 'rejects a tampered encrypted key' do
        expect { decrypt(tamper_segment(token, 1)) }.to raise_error(JWT::Error)
      end

      it 'rejects a tampered iv' do
        expect { decrypt(tamper_segment(token, 2)) }.to raise_error(JWT::DecryptionError, 'JWE decryption failed')
      end

      it 'rejects a tampered ciphertext' do
        expect { decrypt(tamper_segment(token, 3)) }.to raise_error(JWT::DecryptionError, 'JWE decryption failed')
      end

      it 'rejects a tampered authentication tag' do
        expect { decrypt(tamper_segment(token, 4)) }.to raise_error(JWT::DecryptionError, 'JWE decryption failed')
      end
    end

    context 'with dir and A256GCM' do
      let(:token) { described_class.encrypt(payload, cek256, algorithm: 'dir', encryption: 'A256GCM') }

      def decrypt(token)
        described_class.decrypt(token, cek256, algorithms: ['dir'], encryptions: ['A256GCM'])
      end

      include_examples 'tamper resistant token'

      it 'rejects a non-empty encrypted key segment' do
        expect { decrypt(tamper_segment(token, 1)) }.to raise_error(JWT::DecryptionError, 'JWE decryption failed')
      end
    end

    context 'with RSA-OAEP-256 and A128GCM' do
      let(:token) { described_class.encrypt(payload, rsa_public, algorithm: 'RSA-OAEP-256', encryption: 'A128GCM') }

      def decrypt(token)
        described_class.decrypt(token, rsa_key, algorithms: ['RSA-OAEP-256'], encryptions: ['A128GCM'])
      end

      include_examples 'tamper resistant token'

      it 'rejects a tampered encrypted key without leaking details' do
        expect { decrypt(tamper_segment(token, 1)) }.to raise_error(JWT::DecryptionError, 'JWE decryption failed')
      end

      it 'rejects decryption with the wrong private key' do
        wrong_key = OpenSSL::PKey::RSA.generate(2048)
        expect do
          described_class.decrypt(token, wrong_key, algorithms: ['RSA-OAEP-256'], encryptions: ['A128GCM'])
        end.to raise_error(JWT::DecryptionError, 'JWE decryption failed')
      end
    end
  end

  describe 'nested JWS' do
    let(:jws) { JWT.encode({ 'sub' => 'bob' }, 'secret', 'HS256') }
    let(:token) do
      described_class.encrypt(jws, rsa_public, algorithm: 'RSA-OAEP-256', encryption: 'A256GCM', headers: { 'cty' => 'JWT' })
    end

    it 'decrypts first and then verifies the signature with the given policy' do
      decrypted, header = described_class.decrypt(token, rsa_key,
                                                  algorithms: ['RSA-OAEP-256'], encryptions: ['A256GCM'],
                                                  jws: { key: 'secret', algorithms: ['HS256'] })
      expect(decrypted).to eq('sub' => 'bob')
      expect(header['cty']).to eq('JWT')
    end

    it 'accepts a lowercase cty value' do
      token = described_class.encrypt(jws, cek256, algorithm: 'dir', encryption: 'A256GCM', headers: { 'cty' => 'jwt' })
      decrypted, = described_class.decrypt(token, cek256,
                                           algorithms: ['dir'], encryptions: ['A256GCM'],
                                           jws: { key: 'secret', algorithms: ['HS256'] })
      expect(decrypted).to eq('sub' => 'bob')
    end

    it 'refuses to expose claims without an explicit signature policy' do
      expect do
        described_class.decrypt(token, rsa_key, algorithms: ['RSA-OAEP-256'], encryptions: ['A256GCM'])
      end.to raise_error(JWT::JWEError, /signature verification policy/)
    end

    it 'rejects a nested JWS signed with a different key' do
      expect do
        described_class.decrypt(token, rsa_key,
                                algorithms: ['RSA-OAEP-256'], encryptions: ['A256GCM'],
                                jws: { key: 'wrong-secret', algorithms: ['HS256'] })
      end.to raise_error(JWT::VerificationError)
    end

    it 'does not let the nested token widen the signature algorithm policy' do
      expect do
        described_class.decrypt(token, rsa_key,
                                algorithms: ['RSA-OAEP-256'], encryptions: ['A256GCM'],
                                jws: { key: 'secret', algorithms: ['RS256'] })
      end.to raise_error(JWT::IncorrectAlgorithm)
    end

    it 'requires the signature policy to name its algorithms' do
      expect do
        described_class.decrypt(token, rsa_key,
                                algorithms: ['RSA-OAEP-256'], encryptions: ['A256GCM'],
                                jws: { key: 'secret' })
      end.to raise_error(JWT::JWEError, /signature algorithms/)
    end
  end

  describe 'error message hygiene' do
    let(:secret_cek) { 'super-secret-cek-0123456789abcde' }
    let(:token) { described_class.encrypt({ 'sub' => 'alice' }, secret_cek, algorithm: 'dir', encryption: 'A256GCM') }

    it 'does not leak key material or plaintext when the tag is wrong' do
      tampered = tamper_segment(token, 4)
      expect { described_class.decrypt(tampered, secret_cek, algorithms: ['dir'], encryptions: ['A256GCM']) }
        .to raise_error(JWT::DecryptionError) do |error|
          expect(error.message).not_to include(secret_cek)
          expect(error.message).not_to include('alice')
        end
    end

    it 'does not leak key material or plaintext when the key is wrong' do
      wrong_cek = 'x' * 32
      expect { described_class.decrypt(token, wrong_cek, algorithms: ['dir'], encryptions: ['A256GCM']) }
        .to raise_error(JWT::DecryptionError) do |error|
          expect(error.message).not_to include(secret_cek)
          expect(error.message).not_to include('alice')
        end
    end

    it 'does not leak key material or plaintext when RSA unwrapping fails' do
      token = described_class.encrypt({ 'sub' => 'alice' }, rsa_public, algorithm: 'RSA-OAEP-256', encryption: 'A128GCM')
      wrong_key = OpenSSL::PKey::RSA.generate(2048)
      expect { described_class.decrypt(token, wrong_key, algorithms: ['RSA-OAEP-256'], encryptions: ['A128GCM']) }
        .to raise_error(JWT::DecryptionError) do |error|
          expect(error.message).not_to include('alice')
        end
    end
  end
end
