# frozen_string_literal: true

RSpec.describe 'strict JSON decoding' do
  let(:key) { 'secret' }

  def b64(data)
    Base64.urlsafe_encode64(data, padding: false)
  end

  def sign(header, payload, signing_key = key)
    OpenSSL::HMAC.digest('SHA256', signing_key, "#{b64(header)}.#{b64(payload)}")
  end

  def raw_token(header, payload, signature)
    "#{b64(header)}.#{b64(payload)}.#{b64(signature)}"
  end

  describe 'JWT.decode with strict_json: true' do
    context 'when the payload contains duplicate members' do
      let(:header) { '{"alg":"HS256"}' }
      let(:payload) { '{"iss":"good","iss":"evil"}' }
      let(:token) { raw_token(header, payload, sign(header, payload)) }

      it 'collapses the duplicate to the last value in the default permissive mode' do
        decoded, = JWT.decode(token, key, true, algorithms: ['HS256'])
        expect(decoded).to eq('iss' => 'evil')
      end

      it 'raises JWT::DuplicateJSONKeyError with the JSON path and both byte positions' do
        expect do
          JWT.decode(token, key, true, algorithms: ['HS256'], strict_json: true)
        end.to raise_error(JWT::DuplicateJSONKeyError) do |error|
          expect(error.path).to eq('$.iss')
          expect(error.key).to eq('iss')
          expect(error.first_position).to eq(1)
          expect(error.duplicate_position).to eq(payload.index('"iss"', 5))
          expect(error.message).to include('Duplicate member "iss"')
        end
      end

      it 'raises an error recognizable as JWT::DecodeError for callers rescuing the legacy class' do
        expect do
          JWT.decode(token, key, true, algorithms: ['HS256'], strict_json: true)
        end.to raise_error(JWT::DecodeError)
      end
    end

    context 'when the header contains duplicate members' do
      let(:header) { '{"alg":"HS256","alg":"HS256"}' }
      let(:payload) { '{}' }
      let(:token) { raw_token(header, payload, sign(header, payload)) }

      it 'rejects the token before algorithm and signature verification' do
        expect do
          JWT.decode(token, key, true, algorithms: ['HS256'], strict_json: true)
        end.to raise_error(JWT::DuplicateJSONKeyError) do |error|
          expect(error.path).to eq('$.alg')
          expect(header.byteslice(error.first_position, 3)).to eq('"al')
          expect(header.byteslice(error.duplicate_position, 3)).to eq('"al')
        end
      end
    end

    context 'when one issuer key is written with a Unicode escape' do
      let(:header) { '{"alg":"HS256"}' }
      let(:payload) { '{"iss":"good","\u0069ss":"evil"}' }
      let(:token) { raw_token(header, payload, sign(header, payload)) }

      it 'treats the escaped and the literal name as the same member' do
        expect do
          JWT.decode(token, key, true, algorithms: ['HS256'], strict_json: true)
        end.to raise_error(JWT::DuplicateJSONKeyError, /Duplicate member "iss"/) do |error|
          expect(error.key).to eq('iss')
        end
      end
    end

    context 'when braces and quotes only occur inside string values' do
      let(:header) { '{"alg":"HS256"}' }
      let(:payload) do
        sneaky = '{"iss": "looks like an object", "more":'
        '{"a":' + sneaky.to_json + ',"iss":"real"}'
      end
      let(:token) { raw_token(header, payload, sign(header, payload)) }

      it 'parses the string value literally and decodes the token' do
        decoded, = JWT.decode(token, key, true, algorithms: ['HS256'], strict_json: true)
        expect(decoded['a']).to include('{"iss":')
        expect(decoded['iss']).to eq('real')
      end
    end

    context 'with a non JSON object payload' do
      let(:header) { '{"alg":"HS256"}' }
      let(:payload) { '[1,2,3]' }
      let(:token) { raw_token(header, payload, sign(header, payload)) }

      it 'still parses valid JSON strictly' do
        decoded, = JWT.decode(token, key, true, algorithms: ['HS256'], strict_json: true)
        expect(decoded).to eq([1, 2, 3])
      end
    end

    context 'with malformed JSON segments' do
      let(:header) { '{"alg":"HS256"}' }
      let(:payload) { '{"iss": broken}' }
      let(:token) { raw_token(header, payload, sign(header, payload)) }

      it 'raises the recognizable JWT::JSONParseError' do
        expect do
          JWT.decode(token, key, true, algorithms: ['HS256'], strict_json: true)
        end.to raise_error(JWT::JSONParseError) { |error| expect(error.position).to be_a(Integer) }
      end
    end

    describe 'signature binding to the original encoded segments' do
      let(:header) { '{"alg":"HS256"}' }
      let(:ambiguous_payload) { '{"iss":"good","iss":"evil"}' }
      let(:canonical_payload) { ::JSON.generate(::JSON.parse(ambiguous_payload)) }
      let(:ambiguous_token) do
        raw_token(header, ambiguous_payload, sign(header, ambiguous_payload, key))
      end

      it 'never re-serializes JSON: a signature over the re-serialized payload does not verify' do
        canonical_signature = sign(header, canonical_payload, key)
        forged = raw_token(header, ambiguous_payload, canonical_signature)
        expect do
          JWT.decode(forged, key, true, algorithms: ['HS256'], strict_json: true)
        end.to raise_error(JWT::VerificationError, 'Signature verification failed')
      end

      it 'rejects a properly signed ambiguous token instead of accepting one surviving value' do
        expect do
          JWT.decode(ambiguous_token, key, true, algorithms: ['HS256'], strict_json: true)
        end.to raise_error(JWT::DuplicateJSONKeyError)
      end

      it 'keeps the original encoded segments in the signing input' do
        encoded = JWT::EncodedToken.new(ambiguous_token, strict_json: true)
        expect(encoded.signing_input).to eq("#{b64(header)}.#{b64(ambiguous_payload)}")
      end

      it 'accepts a canonically encoded token signed over exactly those bytes' do
        canonical_token = raw_token(header, canonical_payload, sign(header, canonical_payload, key))
        decoded, = JWT.decode(canonical_token, key, true, algorithms: ['HS256'], strict_json: true)
        expect(decoded).to eq('iss' => 'evil')
      end
    end
  end

  describe 'JWT::EncodedToken with strict_json: true' do
    let(:payload) { { 'iss' => 'good' } }
    let(:encoded_token) { JWT.encode(payload, key, 'HS256') }

    it 'defaults to the permissive parser' do
      token = JWT::EncodedToken.new(encoded_token)
      expect(token.unverified_payload).to eq(payload)
    end

    it 'parses a normal token with the strict parser when enabled' do
      token = JWT::EncodedToken.new(encoded_token, strict_json: true)
      expect(token.header).to eq('alg' => 'HS256')
      expect(token.unverified_payload).to eq(payload)
    end

    it 'raises when duplicate members are present in the header' do
      header = '{"alg":"HS256","alg":"none"}'
      raw = raw_token(header, '{}', sign(header, '{}'))
      expect { JWT::EncodedToken.new(raw, strict_json: true).header }
        .to raise_error(JWT::DuplicateJSONKeyError, /\$\.alg/)
    end
  end

  describe 'global configuration' do
    after { JWT.configuration.reset! }

    let(:header) { '{"alg":"HS256"}' }
    let(:payload) { '{"iss":"good","iss":"evil"}' }
    let(:token) { raw_token(header, payload, sign(header, payload)) }

    it 'enables strict decoding through JWT.configure' do
      JWT.configure { |config| config.decode.strict_json = true }
      expect { JWT.decode(token, key, true, algorithms: ['HS256']) }
        .to raise_error(JWT::DuplicateJSONKeyError)
    end

    it 'allows a per-call option to re-enable permissive parsing' do
      JWT.configure { |config| config.decode.strict_json = true }
      decoded, = JWT.decode(token, key, true, algorithms: ['HS256'], strict_json: false)
      expect(decoded).to eq('iss' => 'evil')
    end
  end

  describe 'unencoded payloads (b64: false)' do
    it 'applies strict parsing to the raw payload segment as well' do
      header_json = '{"alg":"HS256","b64":false,"crit":["b64"]}'
      payload_json = '{"iss":"good","iss":"evil"}'
      signature = OpenSSL::HMAC.digest('SHA256', key, "#{b64(header_json)}.#{payload_json}")
      token = "#{b64(header_json)}.#{payload_json}.#{b64(signature)}"

      expect do
        JWT.decode(token, key, true, algorithms: ['HS256'], strict_json: true)
      end.to raise_error(JWT::DuplicateJSONKeyError, /\$\.iss/)
    end
  end

  describe 'decode configuration' do
    it 'defaults strict_json to false' do
      expect(JWT.configuration.decode.strict_json).to eq(false)
      expect(JWT::Configuration::DecodeConfiguration.new.to_h[:strict_json]).to eq(false)
    end
  end
end
