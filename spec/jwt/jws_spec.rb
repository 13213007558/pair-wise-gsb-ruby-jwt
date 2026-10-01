# frozen_string_literal: true

RSpec.describe JWT::JWS do
  let(:key) { 'secret' }
  let(:algorithm) { 'HS256' }

  describe '.sign and .verify with an unencoded payload (RFC 7797, b64=false)' do
    # NUL bytes, non-UTF-8 bytes and periods in the detached payload
    let(:payload) { "\x00binary.\xFF\xFE\x00payload.with.periods\x00".b }
    let(:jws) { described_class.sign(payload, key, algorithm, { b64: false }, detached: true) }

    it 'produces a detached compact serialization with an empty payload segment' do
      _encoded_header, embedded_payload, encoded_signature = jws.split('.', -1)

      expect(embedded_payload).to eq('')
      expect(encoded_signature).not_to be_empty
    end

    it 'adds b64 to the crit header automatically' do
      header = JWT::JSON.parse(JWT::Base64.url_decode(jws.split('.').first))

      expect(header['b64']).to eq(false)
      expect(header['crit']).to include('b64')
    end

    it 'keeps a caller-provided crit header and extends it with b64' do
      jws = described_class.sign(payload, key, algorithm, { b64: false, crit: ['other'] }, detached: true)
      header = JWT::JSON.parse(JWT::Base64.url_decode(jws.split('.').first))

      expect(header['crit']).to contain_exactly('other', 'b64')
    end

    it 'verifies the exact same raw bytes and returns them' do
      expect(described_class.verify(jws, key, algorithm, payload: payload)).to eq(payload)
    end

    it 'fails verification when any single payload byte is changed' do
      payload.bytesize.times do |i|
        tampered = payload.dup
        tampered.setbyte(i, tampered.getbyte(i) ^ 0xFF)

        expect { described_class.verify(jws, key, algorithm, payload: tampered) }
          .to raise_error(JWT::VerificationError), "expected byte #{i} to be covered by the signature"
      end
    end

    it 'does not apply newline or encoding conversions to the provided bytes' do
      jws = described_class.sign("data\r\n", key, algorithm, { b64: false }, detached: true)

      expect(described_class.verify(jws, key, algorithm, payload: "data\r\n")).to eq("data\r\n")
      expect { described_class.verify(jws, key, algorithm, payload: 'data') }.to raise_error(JWT::VerificationError)
      expect { described_class.verify(jws, key, algorithm, payload: "data\n") }.to raise_error(JWT::VerificationError)
    end

    it 'fails verification with a wrong key' do
      expect { described_class.verify(jws, 'wrong', algorithm, payload: payload) }.to raise_error(JWT::VerificationError)
    end

    context 'with an empty payload' do
      let(:empty_jws) { described_class.sign('', key, algorithm, { b64: false }, detached: true) }

      it 'verifies when an empty payload is explicitly provided' do
        expect(described_class.verify(empty_jws, key, algorithm, payload: '')).to eq('')
      end

      it 'raises when the detached payload is not provided at all' do
        expect { described_class.verify(empty_jws, key, algorithm) }
          .to raise_error(JWT::MalformedTokenError, 'Detached payload not provided')
      end
    end

    context 'when the payload is embedded in the compact serialization' do
      it 'embeds payloads without periods as-is' do
        jws = described_class.sign('hello', key, algorithm, { b64: false })

        expect(jws.split('.', -1)[1]).to eq('hello')
        expect(described_class.verify(jws, key, algorithm)).to eq('hello')
      end

      it 'rejects payloads containing a period' do
        expect { described_class.sign('pay.load', key, algorithm, { b64: false }) }
          .to raise_error(JWT::EncodeError, /period/)
      end

      it 'rejects compact serializations with too many segments' do
        expect { described_class.verify('a.b.c.d', key, algorithm) }
          .to raise_error(JWT::MalformedTokenError, 'Not enough or too many segments')
      end

      it 'rejects a payload given both embedded and as an argument' do
        jws = described_class.sign('hello', key, algorithm, { b64: false })

        expect { described_class.verify(jws, key, algorithm, payload: 'hello') }
          .to raise_error(ArgumentError, 'Payload given both embedded in the token and as an argument')
      end
    end

    context 'when the crit header does not list b64' do
      let(:jws) do
        header = JWT::Base64.url_encode(JWT::JSON.generate({ 'alg' => algorithm, 'b64' => false }))
        signing_input = "#{header}.payload"
        signature = JWT::Base64.url_encode(OpenSSL::HMAC.digest('SHA256', key, signing_input))
        "#{header}.payload.#{signature}"
      end

      it 'raises an InvalidCritError' do
        expect { described_class.verify(jws, key, algorithm) }
          .to raise_error(JWT::InvalidCritError, 'Crit header missing expected values: b64')
      end
    end

    context 'when the token algorithm is not allowed' do
      it 'raises an IncorrectAlgorithm error' do
        expect { described_class.verify(jws, key, 'HS512', payload: payload) }
          .to raise_error(JWT::IncorrectAlgorithm, 'Expected a different algorithm')
      end
    end

    context 'when the payload is not a String' do
      it 'raises an ArgumentError on sign' do
        expect { described_class.sign(nil, key, algorithm, { b64: false }, detached: true) }.to raise_error(ArgumentError, 'Payload must be a String')
      end

      it 'raises an ArgumentError on verify' do
        expect { described_class.verify(jws, key, algorithm, payload: 123) }.to raise_error(ArgumentError, 'Payload must be a String')
      end
    end
  end

  describe '.sign and .verify with a base64url-encoded payload (default)' do
    let(:payload) { "\x00binary.\xFF\xFEpayload".b }

    it 'round-trips an embedded payload' do
      jws = described_class.sign(payload, key, algorithm)

      expect(described_class.verify(jws, key, algorithm)).to eq(payload)
    end

    it 'round-trips a detached payload' do
      jws = described_class.sign(payload, key, algorithm, {}, detached: true)

      expect(jws.split('.', -1)[1]).to eq('')
      expect(described_class.verify(jws, key, algorithm, payload: payload)).to eq(payload)
    end

    it 'distinguishes an empty payload from a missing detached payload' do
      jws = described_class.sign('', key, algorithm, {}, detached: true)

      expect(described_class.verify(jws, key, algorithm, payload: '')).to eq('')
      expect { described_class.verify(jws, key, algorithm) }.to raise_error(JWT::MalformedTokenError, 'Detached payload not provided')
    end

    it 'does not require a crit header' do
      jws = described_class.sign(payload, key, algorithm)
      header = JWT::JSON.parse(JWT::Base64.url_decode(jws.split('.').first))

      expect(header).not_to have_key('crit')
    end
  end

  describe 'the JWT claims API' do
    let(:token) do
      JWT::Token.new(payload: { 'pay' => 'load' }, header: { b64: false, crit: ['b64'] }).tap do |t|
        t.sign!(algorithm: algorithm, key: key)
      end
    end

    it 'JWT.decode rejects tokens with an unencoded payload' do
      expect { JWT.decode(token.jwt, key, true, algorithm: algorithm) }
        .to raise_error(JWT::MalformedTokenError, 'Unencoded payload (b64=false) is not supported, use JWT::JWS instead')
    end

    it 'JWT.encode and JWT.decode continue to handle normal JWTs' do
      jwt = JWT.encode({ 'pay' => 'load' }, key, algorithm)

      expect(JWT.decode(jwt, key, true, algorithm: algorithm).first).to eq({ 'pay' => 'load' })
    end
  end
end
