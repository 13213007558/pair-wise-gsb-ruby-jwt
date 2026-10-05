# frozen_string_literal: true

RSpec.describe JWT::JWE::CompactToken do
  # Fixed vector from the panva/jose public EncryptJWT test suite. The key and
  # IV are deterministic, so this also exercises AES-128-GCM against another
  # JOSE implementation.
  DIRECT_VECTOR =
    'eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..AAAAAAAAAAAAAAAA.eKqvvA6MxuqSRbLVFIidFJb8x4lzPytWkoA.aglYAurAaFCoM8sCqaXSyw'
  DIRECT_KEY = ("\0" * 16).freeze

  # Fixed RSA key from this repository and an encrypted token produced by
  # Node WebCrypto using RSA-OAEP-256/MGF1-SHA-256 and AES-256-GCM.
  RSA_VECTOR =
    'eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.' \
      'sDE1SxA7ZXK2s6LzQA5qpaZLju7PoFnF5bCfv3i884OsCy7uAljr3tWYiGyuE5LrbnTX8gqYFpycpoSLMYSwDoyeOf3NJYChy0-ZdoBLofuIePksxvCnv4va4pEcEQ1Stn7Kq4ew9m0pq4LqXjAh-aaxY93-A2lMyk4sFhuXrSe5vU9GHcsNX0BPTVpK3QvsiaSJRZro17Rb961FHJhPh4EJK_S_l6c1-nu9Ntnavpc94W3cQGG0yqUgzzctKWnJKSBm6NKckEtXoY4Y9KnoXE5kRGHjeu2vLrazF2N040t974ajEEuD1TlAj7IaSaFdZjt8R9ncuaxSJiMg8UP_vg.' \
      'CAgICAgICAgICAgI.' \
      'R2Ir7JkZ3Ib8WwwckQWk45U8PN7OqTDzjwN8jQ-BOfnEMQ.' \
      'A9bcdDW9XgklLk1OS2teZA'
  RSA_FIXTURE = OpenSSL::PKey::RSA.new(File.read('spec/fixtures/keys/rsa-2048-private.pem')).freeze
  let(:direct_key) { DIRECT_KEY }
  let(:direct_vector) { DIRECT_VECTOR }
  let(:rsa_private_key) { RSA_FIXTURE }
  let(:rsa_vector) { RSA_VECTOR }

  describe '.decrypt' do
    it 'decrypts the public dir/A128GCM vector' do
      token = described_class.decrypt(direct_vector, direct_key, ['dir'], ['A128GCM'])

      expect(token.header).to eq('alg' => 'dir', 'enc' => 'A128GCM')
      expect(token.plaintext).to eq('{"urn:example:claim":true}')
    end

    it 'decrypts the cross-implementation RSA-OAEP-256/A256GCM vector' do
      token = described_class.decrypt(rsa_vector, rsa_private_key, ['RSA-OAEP-256'], ['A256GCM'])

      expect(JSON.parse(token.plaintext)).to eq('urn' => { 'example' => { 'claim' => true } })
    end

    it 'does not expose plaintext before authentication tag verification' do
      token = described_class.new(direct_vector)

      expect { token.plaintext }.to raise_error(JWT::DecodeError, /Verify the JWE authentication tag/)
    end

    shared_examples 'a rejected algorithm policy' do |algorithms, encryption_algorithms, message|
      it 'rejects the token before decrypting' do
        expect do
          described_class.decrypt(direct_vector, direct_key, algorithms, encryption_algorithms)
        end.to raise_error(JWT::IncorrectAlgorithm, message)
      end
    end

    it_behaves_like 'a rejected algorithm policy', [], ['A128GCM'], 'A key management algorithm must be specified'
    it_behaves_like 'a rejected algorithm policy', ['dir'], [], 'A content encryption algorithm must be specified'
    it_behaves_like 'a rejected algorithm policy', ['RSA-OAEP-256'], ['A128GCM'], 'Expected a different algorithm'
    it_behaves_like 'a rejected algorithm policy', ['dir'], ['A256GCM'], 'Expected a different encryption algorithm'

    {
      'header' => [DIRECT_VECTOR, DIRECT_KEY, ['dir'], ['A128GCM']],
      'encrypted key' => [RSA_VECTOR, RSA_FIXTURE, ['RSA-OAEP-256'], ['A256GCM']],
      'initialization vector' => [DIRECT_VECTOR, DIRECT_KEY, ['dir'], ['A128GCM']],
      'ciphertext' => [DIRECT_VECTOR, DIRECT_KEY, ['dir'], ['A128GCM']],
      'authentication tag' => [DIRECT_VECTOR, DIRECT_KEY, ['dir'], ['A128GCM']]
    }.each_with_index do |(name, input), index|
      context "when #{name} is tampered with" do
        let(:segments) { input.first.split('.') }
        let(:key) { input[1] }
        let(:algorithms) { input[2] }
        let(:encryption_algorithms) { input[3] }

        it 'raises a generic error without plaintext or key material' do
          if index.zero?
            header = JSON.parse(Base64.urlsafe_decode64(segments[index]))
            header['alg'] = 'RSA-OAEP-256'
            segments[index] = Base64.urlsafe_encode64(header.to_json)
            token = described_class.new(segments.join('.'))
            expected_error = JWT::IncorrectAlgorithm
          else
            bytes = Base64.urlsafe_decode64(segments[index])
            bytes.setbyte(-1, bytes.getbyte(-1) ^ 1)
            segments[index] = Base64.urlsafe_encode64(bytes)
            token = described_class.new(segments.join('.'))
            expected_error = JWT::VerificationError
          end

          expect do
            token.decrypt(key: key, algorithms: algorithms, encryption_algorithms: encryption_algorithms)
          end.to raise_error(expected_error)
          expect { token.plaintext }.to raise_error(JWT::DecodeError)
        end
      end
    end

    it 'does not include plaintext in tag failure messages' do
      segments = direct_vector.split('.')
      segments[4] = Base64.urlsafe_encode64('0' * 16)
      expect do
        described_class.decrypt(segments.join('.'), direct_key, ['dir'], ['A128GCM'])
      end.to raise_error(JWT::VerificationError) { |error| expect(error.message).not_to include('urn', 'claim') }
    end

    it 'rejects unsupported protected extension headers' do
      header = Base64.urlsafe_encode64({ alg: 'dir', enc: 'A128GCM', zip: 'DEF' }.to_json)
      segments = direct_vector.split('.')
      segments[0] = header

      expect do
        described_class.decrypt(segments.join('.'), direct_key, ['dir'], ['A128GCM'])
      end.to raise_error(JWT::IncorrectAlgorithm, 'Unsupported JWE header parameter')
    end

    it 'accepts an oct JWK as the direct encryption key' do
      jwk = JWT::JWK.import(kty: 'oct', k: Base64.urlsafe_encode64(direct_key))

      token = described_class.decrypt(direct_vector, jwk, ['dir'], ['A128GCM'])

      expect(token.plaintext).to include('claim')
    end
  end

  describe '.encrypt' do
    it 'round-trips direct A256GCM encryption' do
      key = SecureRandom.random_bytes(32)
      encrypted = described_class.encrypt('plaintext', key: key, algorithm: 'dir', encryption_algorithm: 'A256GCM')
      decrypted = described_class.decrypt(encrypted, key, ['dir'], ['A256GCM'])

      expect(decrypted.plaintext).to eq('plaintext')
    end

    it 'round-trips RSA-OAEP-256 with A128GCM' do
      encrypted = described_class.encrypt('plaintext', key: rsa_private_key.public_key, algorithm: 'RSA-OAEP-256', encryption_algorithm: 'A128GCM')
      decrypted = described_class.decrypt(encrypted, rsa_private_key, ['RSA-OAEP-256'], ['A128GCM'])

      expect(decrypted.plaintext).to eq('plaintext')
    end
  end
end
