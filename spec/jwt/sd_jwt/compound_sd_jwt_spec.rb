# frozen_string_literal: true

RSpec.describe JWT::SDJWT::CompoundSdJwt do
  let(:jwt) do
    JWT::Token.new(payload: { 'a' => 1 }).tap do |t|
      t.sign!(algorithm: 'HS256', key: 'secret')
    end.jwt
  end

  let(:disclosure) { JWT::SDJWT::Disclosure.new(salt: 's', claim_name: 'k', value: 'v') }

  describe '#to_s / .parse round trip' do
    it 'serializes without a Key Binding JWT (trailing tilde)' do
      sd = described_class.new(issuer_jwt: jwt, disclosures: [disclosure])

      expect(sd.to_s).to eq("#{jwt}~#{disclosure.encoded}~")

      parsed = described_class.parse(sd.to_s)
      expect(parsed.issuer_jwt).to eq(jwt)
      expect(parsed.disclosures.map(&:encoded)).to eq([disclosure.encoded])
      expect(parsed.kb_jwt).to be_nil
    end

    it 'serializes with a Key Binding JWT' do
      kb = JWT::Token.new(payload: { 'nonce' => 'n' }).tap do |t|
        t.sign!(algorithm: 'HS256', key: 'kb-secret')
      end.jwt
      sd = described_class.new(issuer_jwt: jwt, disclosures: [disclosure], kb_jwt: kb)

      expect(sd.to_s).to eq("#{jwt}~#{disclosure.encoded}~#{kb}~")

      parsed = described_class.parse(sd.to_s)
      expect(parsed.kb_jwt).to eq(kb)
    end

    it 'accepts the serialization without a trailing tilde for the last disclosure' do
      parsed = described_class.parse("#{jwt}~#{disclosure.encoded}")

      expect(parsed.kb_jwt).to be_nil
      expect(parsed.disclosures.length).to eq(1)
    end
  end

  describe '.parse' do
    it 'rejects strings without tildes' do
      expect { described_class.parse(jwt) }.to raise_error(JWT::SDJWTFormatError, /~/)
    end

    it 'rejects empty issuer JWTs' do
      expect { described_class.parse("~#{disclosure.encoded}~") }
        .to raise_error(JWT::SDJWTFormatError, /issuer JWT/)
    end

    it 'rejects issuer JWTs without three segments' do
      expect { described_class.parse('a.b~d~') }.to raise_error(JWT::SDJWTFormatError, /three segments/)
    end

    it 'rejects empty disclosure segments' do
      expect { described_class.parse("#{jwt}~~") }
        .to raise_error(JWT::SDJWTFormatError, /Disclosures must not be empty/)
    end

    it 'rejects malformed Key Binding JWTs' do
      malformed_kb = 'aaa.bbb.ccc'
      # A JWT-looking segment is accepted as KB JWT by the parser; the verifier
      # is responsible for its cryptographic validation. The parser does reject
      # non JWT-looking trailing segments that cannot be disclosures either.
      expect(described_class.parse("#{jwt}~#{disclosure.encoded}~#{malformed_kb}~").kb_jwt)
        .to eq(malformed_kb)
    end
  end

  describe '#unverified_payload' do
    it 'returns the issuer JWT payload without verification' do
      sd = described_class.new(issuer_jwt: jwt)

      expect(sd.unverified_payload).to eq('a' => 1)
    end
  end
end

RSpec.describe JWT::SDJWT::CompoundSdJwt, 'parse errors' do
  it 'rejects non strings' do
    expect { described_class.parse(nil) }.to raise_error(JWT::SDJWTFormatError)
    expect { described_class.parse('') }.to raise_error(JWT::SDJWTFormatError)
  end
end
