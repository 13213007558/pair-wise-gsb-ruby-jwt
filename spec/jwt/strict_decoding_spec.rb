# frozen_string_literal: true

RSpec.describe 'strict JSON decoding' do
  let(:key) { 'secret' }
  let(:header_json) { '{"alg":"HS256","typ":"JWT"}' }
  let(:encoded_header) { JWT::Base64.url_encode(header_json) }

  def signed_token(payload_json, signing_key: key, header: encoded_header)
    signing_input = "#{header}.#{JWT::Base64.url_encode(payload_json)}"
    signature = JWT::Base64.url_encode(OpenSSL::HMAC.digest('SHA256', signing_key, signing_input))
    "#{signing_input}.#{signature}"
  end

  context 'when strict_decoding is disabled' do
    it 'keeps the last value for duplicate keys' do
      token = signed_token('{"iss":"first","iss":"second"}')
      payload, = JWT.decode(token, key, true, algorithm: 'HS256')
      expect(payload['iss']).to eq('second')
    end
  end

  context 'when strict_decoding is enabled' do
    it 'decodes a regular token' do
      token = JWT.encode({ 'iss' => 'me', 'nested' => { 'a' => [1, 2] } }, key, 'HS256')
      payload, header = JWT.decode(token, key, true, algorithm: 'HS256', strict_decoding: true)
      expect(payload).to eq('iss' => 'me', 'nested' => { 'a' => [1, 2] })
      expect(header['alg']).to eq('HS256')
    end

    it 'rejects a payload with a duplicate issuer' do
      token = signed_token('{"iss":"first","iss":"second"}')
      expect { JWT.decode(token, key, true, algorithm: 'HS256', strict_decoding: true) }
        .to raise_error(JWT::StrictDecodingError, 'Duplicate key "iss" at $.iss')
    end

    it 'rejects a payload with a unicode-escaped duplicate issuer' do
      token = signed_token('{"iss":"first","\\u0069ss":"second"}')
      expect { JWT.decode(token, key, true, algorithm: 'HS256', strict_decoding: true) }
        .to raise_error(JWT::StrictDecodingError, 'Duplicate key "iss" at $.iss')
    end

    it 'reports the JSON path and byte offsets of both key occurrences' do
      token = signed_token('{"iss":"first","iss":"second"}')
      error = nil
      begin
        JWT.decode(token, key, true, algorithm: 'HS256', strict_decoding: true)
      rescue JWT::StrictDecodingError => e
        error = e
      end
      expect(error.path).to eq('$.iss')
      expect(error.key).to eq('iss')
      expect(error.first_offset).to eq(1)
      expect(error.second_offset).to eq(15)
    end

    it 'rejects duplicates nested anywhere in the payload' do
      token = signed_token('{"a":{"b":[{"iss":1,"iss":2}]}}')
      expect { JWT.decode(token, key, true, algorithm: 'HS256', strict_decoding: true) }
        .to raise_error(JWT::StrictDecodingError, 'Duplicate key "iss" at $.a.b[0].iss')
    end

    it 'rejects duplicates in the header' do
      token = signed_token('{"sub":"1"}', header: JWT::Base64.url_encode('{"alg":"HS256","alg":"HS256"}'))
      expect { JWT.decode(token, key, true, algorithm: 'HS256', strict_decoding: true) }
        .to raise_error(JWT::StrictDecodingError, 'Duplicate key "alg" at $.alg')
    end

    it 'is not confused by braces and quotes inside string values' do
      token = signed_token('{"a":"}{\\"","iss":"me"}')
      payload, = JWT.decode(token, key, true, algorithm: 'HS256', strict_decoding: true)
      expect(payload).to eq('a' => '}{"', 'iss' => 'me')
    end

    it 'raises errors that are recognizable as JWT decoding errors' do
      token = signed_token('{"iss":"first","iss":"second"}')
      expect { JWT.decode(token, key, true, algorithm: 'HS256', strict_decoding: true) }
        .to raise_error(JWT::MalformedTokenError)
    end

    it 'enforces the size limit when given as an option' do
      token = signed_token('{"iss":"me"}')
      expect { JWT.decode(token, key, true, algorithm: 'HS256', strict_decoding: { max_size: 5 }) }
        .to raise_error(JWT::StrictDecodingError, /exceeds the limit of 5 bytes/)
    end

    it 'enforces the depth limit when given as an option' do
      token = signed_token('{"a":{"b":{"c":1}}}')
      expect { JWT.decode(token, key, true, algorithm: 'HS256', strict_decoding: { max_depth: 2 }) }
        .to raise_error(JWT::StrictDecodingError, /nesting depth exceeds the limit of 2/)
    end

    it 'raises MalformedTokenError for invalid JSON' do
      token = signed_token('{"iss":}')
      expect { JWT.decode(token, key, true, algorithm: 'HS256', strict_decoding: true) }
        .to raise_error(JWT::MalformedTokenError, 'Invalid segment encoding')
    end

    context 'signature verification' do
      it 'verifies the signature against the original encoded segments' do
        token = JWT.encode({ 'iss' => 'me' }, key, 'HS256')
        expect(JWT.decode(token, key, true, algorithm: 'HS256', strict_decoding: true).first)
          .to eq('iss' => 'me')
      end

      it 'rejects a token whose payload was re-serialized after signing' do
        # The signature was computed over the original payload JSON containing
        # duplicate keys. Re-serializing the JSON (which drops the duplicate)
        # must not make the signature valid: verification uses the original
        # encoded segments, not a re-serialization of the parsed JSON.
        original_payload_json = '{"iss":"first","iss":"second"}'
        token = signed_token(original_payload_json)
        reserialized_payload = JWT::Base64.url_encode(JSON.generate(JSON.parse(original_payload_json)))
        tampered = "#{encoded_header}.#{reserialized_payload}.#{token.split('.').last}"

        expect { JWT.decode(tampered, key, true, algorithm: 'HS256', strict_decoding: true) }
          .to raise_error(JWT::VerificationError)
      end

      it 'rejects a valid strict token signed with a different key' do
        token = signed_token('{"iss":"me"}', signing_key: 'other')
        expect { JWT.decode(token, key, true, algorithm: 'HS256', strict_decoding: true) }
          .to raise_error(JWT::VerificationError)
      end
    end
  end

  context 'when strict_decoding is enabled via global configuration' do
    before { JWT.configuration.decode.strict_decoding = true }
    after { JWT.configuration.decode.strict_decoding = false }

    it 'rejects duplicate keys' do
      token = signed_token('{"iss":"first","iss":"second"}')
      expect { JWT.decode(token, key, true, algorithm: 'HS256') }
        .to raise_error(JWT::StrictDecodingError)
    end
  end

  describe JWT::EncodedToken do
    it 'supports strict decoding directly' do
      token = JWT.encode({ 'iss' => 'me' }, key, 'HS256')
      encoded_token = JWT::EncodedToken.new(token, strict_decoding: true)
      encoded_token.verify_signature!(algorithm: 'HS256', key: key)
      expect(encoded_token.unverified_payload).to eq('iss' => 'me')
    end

    it 'rejects duplicate keys directly' do
      token = JWT.encode({ 'iss' => 'me' }, key, 'HS256')
      segments = token.split('.')
      segments[1] = JWT::Base64.url_encode('{"iss":"a","iss":"b"}')
      encoded_token = JWT::EncodedToken.new(segments.join('.'), strict_decoding: true)
      expect { encoded_token.unverified_payload }.to raise_error(JWT::StrictDecodingError)
    end
  end
end
