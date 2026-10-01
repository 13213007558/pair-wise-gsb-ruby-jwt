# frozen_string_literal: true

RSpec.describe JWT::SDJWT::Disclosure do
  describe 'object member disclosure' do
    subject(:disclosure) { described_class.new(salt: 'salt', claim_name: 'name', value: 'Alice') }

    it 'serializes as a three element JSON array' do
      expect(JSON.parse(JWT::Base64.url_decode(disclosure.encoded)))
        .to eq(['salt', 'name', 'Alice'])
    end

    it 'round trips through encoding' do
      parsed = described_class.from_encoded(disclosure.encoded)

      expect(parsed.salt).to eq('salt')
      expect(parsed.claim_name).to eq('name')
      expect(parsed.value).to eq('Alice')
      expect(parsed.encoded).to eq(disclosure.encoded)
    end

    it 'computes the SHA-256 digest over the encoded disclosure' do
      expected = OpenSSL::Digest::SHA256.hexdigest(disclosure.encoded)

      expect(disclosure.digest).to eq(expected)
    end
  end

  describe 'array element disclosure' do
    subject(:disclosure) { described_class.new(salt: 'salt', value: 'CN') }

    it 'serializes as a two element JSON array' do
      expect(JSON.parse(JWT::Base64.url_decode(disclosure.encoded))).to eq(['salt', 'CN'])
      expect(disclosure.claim_name).to be_nil
    end

    it 'round trips through encoding' do
      parsed = described_class.from_encoded(disclosure.encoded)

      expect(parsed.claim_name).to be_nil
      expect(parsed.value).to eq('CN')
    end
  end

  describe '.from_encoded' do
    def encode(data)
      JWT::Base64.url_encode(JSON.generate(data))
    end

    it 'rejects non JSON arrays' do
      expect { described_class.from_encoded(encode('x' => 1)) }
        .to raise_error(JWT::SDJWTFormatError, /JSON array/)
    end

    it 'rejects arrays with the wrong size' do
      expect { described_class.from_encoded(encode(['one'])) }
        .to raise_error(JWT::SDJWTFormatError, /two or three/)
      expect { described_class.from_encoded(encode(%w[a b c d])) }
        .to raise_error(JWT::SDJWTFormatError, /two or three/)
    end

    it 'rejects empty salts' do
      expect { described_class.from_encoded(encode(['', 'name', 'v'])) }
        .to raise_error(JWT::SDJWTFormatError, /salt/)
    end

    it 'rejects empty object member names' do
      expect { described_class.from_encoded(encode(['salt', '', 'v'])) }
        .to raise_error(JWT::SDJWTFormatError, /claim name/)
    end

    it 'rejects invalid base64url' do
      expect { described_class.from_encoded('!!!not-base64!!!') }
        .to raise_error(JWT::SDJWTFormatError)
    end

    it 'rejects empty strings' do
      expect { described_class.from_encoded('') }
        .to raise_error(JWT::SDJWTFormatError)
    end
  end
end

RSpec.describe JWT::SDJWT::Disclosure, 'malformed JSON' do
  it 'raises when the decoded content is not JSON' do
    encoded = JWT::Base64.url_encode('not-json')

    expect { described_class.from_encoded(encoded) }
      .to raise_error(JWT::SDJWTFormatError, /valid JSON/)
  end
end
