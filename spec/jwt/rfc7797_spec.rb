# frozen_string_literal: true

# Tests for RFC 7797 "JSON Web Signature (JWS) Unencoded Payload Option".
# The feature lives on the low level JWS interfaces (JWT::Token /
# JWT::EncodedToken). The JWT claims API (JWT.encode / JWT.decode) keeps
# accepting only regular JWTs.
RSpec.describe 'RFC 7797 unencoded payload (b64=false)' do
  let(:key) { 'shh-secret-key-please-use-enough-bytes' }
  # Payload containing a NUL byte, non UTF-8 bytes and period characters.
  let(:raw_payload) do
    (+ "a\x00b\xFF\xFE.with.dots\n\r\t").force_encoding(Encoding::BINARY)
  end

  def build_signed_token(payload: raw_payload, header: {})
    JWT::Token.new(payload: payload, header: { 'b64' => false }.merge(header)).tap do |token|
      token.sign!(algorithm: 'HS256', key: key)
      token.detach_payload!
    end
  end

  describe 'signing with JWT::Token' do
    it 'uses the raw payload bytes as the signing input' do
      token = JWT::Token.new(payload: raw_payload, header: { 'b64' => false })
      token.sign!(algorithm: 'HS256', key: key)

      expect(token.encoded_payload).to eq(raw_payload)
      expect(token.signing_input).to eq("#{token.encoded_header}.#{raw_payload}")
    end

    it 'produces a detached compact serialization by default recommendation' do
      token = build_signed_token

      expect(token.jwt.count('.')).to eq(2)
      expect(token.jwt.split('.')[1]).to eq('')
    end

    it 'declares b64 in the crit header automatically' do
      token = build_signed_token

      expect(token.header['b64']).to be(false)
      expect(token.header['crit']).to eq(['b64'])
    end

    it 'does not duplicate b64 when crit already contains it' do
      token = build_signed_token(header: { 'crit' => ['b64'] })

      expect(token.header['crit']).to eq(['b64'])
    end

    it 'preserves other crit values' do
      token = build_signed_token(header: { 'crit' => ['http://example.invalid/other'] })

      expect(token.header['crit']).to eq(['http://example.invalid/other', 'b64'])
    end

    it 'raises when crit is not an array' do
      token = JWT::Token.new(payload: raw_payload, header: { 'b64' => false, 'crit' => 'b64' })

      expect { token.sign!(algorithm: 'HS256', key: key) }.to raise_error(JWT::EncodeError, 'The crit header must be an Array')
    end

    it 'allows an inline payload without a period character' do
      token = JWT::Token.new(payload: 'plain-payload', header: { 'b64' => false })
      token.sign!(algorithm: 'HS256', key: key)

      expect(token.jwt.split('.')[1]).to eq('plain-payload')
    end

    it 'refuses an inline payload containing a period and requires the detached form' do
      token = JWT::Token.new(payload: 'pay.load', header: { 'b64' => false })
      token.sign!(algorithm: 'HS256', key: key)

      expect { token.jwt }.to raise_error(JWT::EncodeError, "Invalid unencoded payload, '.' character is not allowed in the payload")
    end

    it 'supports an empty payload' do
      token = build_signed_token(payload: '')

      encoded = JWT::EncodedToken.new(token.jwt)
      encoded.encoded_payload = ''

      expect(encoded.valid_signature?(algorithm: 'HS256', key: key)).to be(true)
      expect(encoded.unverified_payload).to eq('')
    end
  end

  describe 'verifying with JWT::EncodedToken' do
    subject(:encoded) do
      JWT::EncodedToken.new(build_signed_token.jwt)
    end

    it 'verifies when the exact original bytes are provided' do
      encoded.encoded_payload = raw_payload

      expect(encoded.verify_signature!(algorithm: 'HS256', key: key)).to be_nil
    end

    it 'returns the raw bytes without parsing or encoding conversion' do
      encoded.encoded_payload = raw_payload
      encoded.verify_signature!(algorithm: 'HS256', key: key)

      expect(encoded.unverified_payload).to eq(raw_payload)
      expect(encoded.unverified_payload.encoding).to eq(Encoding::BINARY)
    end

    it 'does not perform any newline or base64 processing on the payload' do
      token = build_signed_token
      candidate = JWT::EncodedToken.new(token.jwt)
      candidate.encoded_payload = raw_payload.gsub("\n", "\r\n")

      expect(candidate.valid_signature?(algorithm: 'HS256', key: key)).to be(false)
    end

    it 'fails when one byte is flipped' do
      tampered = raw_payload.dup
      tampered.setbyte(0, tampered.getbyte(0) ^ 0x01)
      encoded.encoded_payload = tampered

      expect(encoded.valid_signature?(algorithm: 'HS256', key: key)).to be(false)
    end

    it 'fails when a byte is appended' do
      encoded.encoded_payload = raw_payload + 'x'

      expect(encoded.valid_signature?(algorithm: 'HS256', key: key)).to be(false)
    end

    it 'fails when a byte is removed' do
      encoded.encoded_payload = raw_payload[0..-2]

      expect(encoded.valid_signature?(algorithm: 'HS256', key: key)).to be(false)
    end

    it 'treats a missing external payload as an error, distinct from an empty one' do
      empty = build_signed_token(payload: '')
      candidate = JWT::EncodedToken.new(empty.jwt)

      expect { JWT::EncodedToken.new(empty.jwt).verify_signature!(algorithm: 'HS256', key: key) }
        .to raise_error(JWT::MalformedTokenError, 'The payload is detached and must be provided separately')

      candidate.encoded_payload = ''

      expect { candidate.verify_signature!(algorithm: 'HS256', key: key) }.not_to raise_error
    end

    it 'raises a structural error instead of silently verifying a detached token without payload' do
      expect { encoded.valid_signature?(algorithm: 'HS256', key: key) }
        .to raise_error(JWT::MalformedTokenError, 'The payload is detached and must be provided separately')
    end

    it 'accepts a detached payload containing periods' do
      token = build_signed_token(payload: '$.02.with.dots')
      candidate = JWT::EncodedToken.new(token.jwt)
      candidate.encoded_payload = '$.02.with.dots'

      expect(candidate.verify_signature!(algorithm: 'HS256', key: key)).to be_nil
    end

    it 'only accepts a String payload with the original bytes' do
      expect { encoded.encoded_payload = nil }
        .to raise_error(JWT::MalformedTokenError, 'The payload must be a String containing the original bytes')
      expect { encoded.encoded_payload = 42 }
        .to raise_error(JWT::MalformedTokenError, 'The payload must be a String containing the original bytes')
    end

    it 'rejects a non boolean b64 header' do
      header = JWT::Base64.url_encode(JSON.generate(alg: 'HS256', b64: 'false'))
      token = JWT::EncodedToken.new("#{header}..sig")

      expect { token.verify_signature!(algorithm: 'HS256', key: key) }
        .to raise_error(JWT::MalformedTokenError, "The 'b64' header must be a boolean value")
    end

    it 'requires b64 to be part of the crit header' do
      header = JWT::Base64.url_encode(JSON.generate(alg: 'HS256', b64: false))
      token = JWT::EncodedToken.new("#{header}..sig")

      expect { token.verify_signature!(algorithm: 'HS256', key: key) }
        .to raise_error(JWT::MalformedTokenError, "The 'b64' critical header must be declared in the crit header")
    end

    it 'requires the crit header to list b64' do
      header = JWT::Base64.url_encode(JSON.generate(alg: 'HS256', b64: false, crit: ['other']))
      token = JWT::EncodedToken.new("#{header}..sig")

      expect { token.verify_signature!(algorithm: 'HS256', key: key) }
        .to raise_error(JWT::MalformedTokenError, "The 'b64' critical header must be declared in the crit header")
    end

    it 'rejects compact tokens with too many segments' do
      token = JWT::EncodedToken.new('a.b.c.d')

      expect { token.valid_signature?(algorithm: 'HS256', key: key) }
        .to raise_error(JWT::MalformedTokenError, 'Not enough or too many segments')
    end

    it 'rejects inline unencoded payloads with periods' do
      token = build_signed_token(payload: '$.02')
      header_segment = token.jwt.split('.')[0]
      signature_segment = token.jwt.split('.')[2]
      inline = "#{header_segment}.$.02.#{signature_segment}"
      # The period in the payload makes the compact form ambiguous (4 segments)
      expect(inline.split('.').length).to eq(4)
      candidate = JWT::EncodedToken.new(inline)

      expect { candidate.valid_signature?(algorithm: 'HS256', key: key) }
        .to raise_error(JWT::MalformedTokenError, 'Not enough or too many segments')
    end
  end

  describe 'the RFC 7797 section 3.1 test vector' do
    let(:rfc_key) do
      JWT::Base64.url_decode('AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow')
    end
    let(:detached_jws) do
      'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY'
    end

    it 'verifies the $.02 payload supplied detached' do
      token = JWT::EncodedToken.new(detached_jws)
      token.encoded_payload = '$.02'

      expect(token.verify_signature!(algorithm: 'HS256', key: rfc_key)).to be_nil
    end

    it 'fails with any other payload' do
      token = JWT::EncodedToken.new(detached_jws)
      token.encoded_payload = '$.03'

      expect(token.valid_signature?(algorithm: 'HS256', key: rfc_key)).to be(false)
    end
  end

  describe 'the JWT claims API' do
    it 'JWT.encode refuses to produce an unencoded JWS' do
      expect { JWT.encode({ 'a' => 1 }, 'secret', 'HS256', { 'b64' => false }) }
        .to raise_error(JWT::EncodeError, /RFC 7797/)
    end

    it 'JWT.decode refuses an unencoded JWS even with verification disabled' do
      token = build_signed_token

      expect { JWT.decode(token.jwt, key, false, algorithm: 'HS256') }
        .to raise_error(JWT::DecodeError, /RFC 7797/)
    end
  end
end
