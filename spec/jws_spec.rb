# frozen_string_literal: true

RSpec.describe JWT::JWS do
  let(:payload) { { 'sub' => '42', 'exp' => Time.now.to_i + 100 } }
  let(:secret_a) { 'secret-a-that-is-long-enough' }
  let(:secret_b) { 'secret-b-that-is-long-enough' }

  let(:signers) do
    [
      { algorithm: 'HS256', key: secret_a, kid: 'a' },
      { algorithm: 'HS256', key: secret_b, kid: 'b' }
    ]
  end

  let(:verifiers) do
    [
      { algorithm: 'HS256', key: secret_a, kid: 'a' },
      { algorithm: 'HS256', key: secret_b, kid: 'b' }
    ]
  end

  def deep_duplicate(object)
    ::JSON.parse(::JSON.generate(object))
  end

  describe '.sign' do
    it 'produces a General JSON Serialization with one member per signer' do
      jws = described_class.sign(payload, signers)

      expect(jws).to include('payload', 'signatures')
      expect(jws['signatures'].size).to eq(2)
      expect(jws['signatures']).to all(include('protected', 'signature'))
    end

    it 'signs the same payload with independent keys' do
      jws = described_class.sign(payload, signers)

      result = described_class.verify(jws, algorithms: ['HS256'], signers: verifiers, policy: :all)
      expect(result).to be_verified
      expect(result.signatures.map(&:valid?)).to eq([true, true])
    end

    it 'accepts a JSON string as input' do
      jws = described_class.sign(payload, signers)

      result = described_class.verify(::JSON.generate(jws), algorithms: ['HS256'], signers: verifiers)
      expect(result).to be_verified
    end

    it 'rejects overlapping protected and unprotected headers' do
      signers.first[:header] = { 'kid' => 'a' }

      expect { described_class.sign(payload, signers) }
        .to raise_error(JWT::EncodeError, /must not share parameters/)
    end

    it 'does not duplicate a kid provided through protected_header' do
      signers.first[:protected_header] = { 'kid' => 'a' }
      signers.first.delete(:kid)

      jws = described_class.sign(payload, signers)
      encoded_header = jws['signatures'].first['protected']
      header = ::JSON.parse(Base64.urlsafe_decode64(encoded_header))
      expect(header['kid']).to eq('a')
    end

    it 'places unprotected headers in the header member' do
      signers.first[:header] = { 'custom' => 'value' }

      jws = described_class.sign(payload, signers)
      expect(jws['signatures'].first['header']).to eq('custom' => 'value')
    end

    it 'validates numeric claims before signing' do
      expect { described_class.sign({ 'exp' => 'soon' }, signers) }
        .to raise_error(JWT::InvalidPayload)
    end
  end

  describe '.sign_flattened' do
    it 'produces the Flattened syntax' do
      jws = described_class.sign_flattened(payload, signers.first)

      expect(jws).to include('payload', 'protected', 'signature')
      expect(jws).not_to include('signatures')
    end

    it 'round trips with fixed keys' do
      jws = described_class.sign_flattened(payload, signers.first)

      result = described_class.verify(jws, algorithms: ['HS256'], keys: [secret_a])
      expect(result).to be_verified
      expect(result.claims).to eq(payload)
    end
  end

  describe '.verify' do
    let(:jws) { described_class.sign(payload, signers) }

    it 'reports every signature independently' do
      tampered = deep_duplicate(jws)
      tampered['signatures'][1]['signature'] = tampered['signatures'][0]['signature']

      result = described_class.verify(tampered, algorithms: ['HS256'], signers: verifiers, policy: :all)
      expect(result.signatures.map(&:index)).to eq([0, 1])
      expect(result.signatures[0]).to be_valid
      expect(result.signatures[1]).not_to be_valid
      expect(result.signatures[1].error).to match(/Signature verification failed/)
    end

    it 'does not let one valid signature mask another invalid signature' do
      tampered = deep_duplicate(jws)
      tampered['signatures'][1]['signature'] = tampered['signatures'][0]['signature']

      result = described_class.verify(tampered, algorithms: ['HS256'], signers: verifiers, policy: :all)
      expect(result).not_to be_verified
      expect(result.error).to match(/Expected all 2 signer/)
      expect { result.claims }.to raise_error(JWT::TokenError)
    end

    it 'rejects a signature whose alg was shifted into the unprotected header' do
      shifted = deep_duplicate(jws)
      member = shifted['signatures'][0]
      protected_header = ::JSON.parse(Base64.urlsafe_decode64(member['protected']))
      member['header'] = { 'alg' => protected_header.delete('alg') }
      member['protected'] = Base64.urlsafe_encode64(::JSON.generate(protected_header), padding: false)

      result = described_class.verify(shifted, algorithms: ['HS256'], signers: verifiers, policy: :all)
      expect(result).not_to be_verified
      expect(result.signatures[0]).not_to be_valid
    end

    it 'rejects a signature whose kid was shifted into the unprotected header' do
      shifted = deep_duplicate(jws)
      member = shifted['signatures'][0]
      protected_header = ::JSON.parse(Base64.urlsafe_decode64(member['protected']))
      member['header'] = { 'kid' => protected_header.delete('kid') }
      member['protected'] = Base64.urlsafe_encode64(::JSON.generate(protected_header), padding: false)

      result = described_class.verify(shifted, algorithms: ['HS256'], signers: verifiers, policy: :all)
      expect(result).not_to be_verified
      expect(result.signatures[0].error).to match(/No verification key available|Signature verification failed/)
    end

    it 'rejects repeated header parameters between protected and unprotected headers' do
      duplicated = deep_duplicate(jws)
      duplicated['signatures'][0]['header'] = { 'alg' => 'HS256' }

      result = described_class.verify(duplicated, algorithms: ['HS256'], signers: verifiers, policy: :all)
      expect(result.signatures[0]).not_to be_valid
      expect(result.signatures[0].error).to match(/must not be repeated/)
    end

    it 'reports a missing signature as an invalid signature member' do
      missing = deep_duplicate(jws)
      missing['signatures'][1].delete('signature')

      result = described_class.verify(missing, algorithms: ['HS256'], signers: verifiers, policy: :all)
      expect(result).not_to be_verified
      expect(result.signatures[1]).not_to be_valid
      expect(result.signatures[1].error).to match(/missing the signature value/)
    end

    it 'requires an algorithm whitelist from the caller' do
      expect { described_class.verify(jws, signers: verifiers) }
        .to raise_error(JWT::IncorrectAlgorithm, /algorithm must be specified/)
    end

    it 'rejects an algorithm outside the whitelist' do
      result = described_class.verify(jws, algorithms: ['RS256'], signers: verifiers, policy: :all)
      expect(result).not_to be_verified
      expect(result.signatures.map(&:valid?)).to eq([false, false])
    end

    it 'does not ignore unknown crit parameters' do
      signed = described_class.sign(payload, [
        { algorithm: 'HS256', key: secret_a, kid: 'a', protected_header: { 'crit' => ['http://example.invalid/UNKNOWN'], 'http://example.invalid/UNKNOWN' => true } }
      ])

      result = described_class.verify(signed, algorithms: ['HS256'], signers: [{ algorithm: 'HS256', key: secret_a, kid: 'a' }], policy: :all)
      expect(result).not_to be_verified
      expect(result.signatures[0].error).to match(/Unknown critical header parameters/)
    end

    it 'accepts crit parameters explicitly understood by the caller' do
      signed = described_class.sign(payload, [
        { algorithm: 'HS256', key: secret_a, kid: 'a', protected_header: { 'crit' => ['custom'], 'custom' => 'yes' } }
      ])

      result = described_class.verify(signed, algorithms: ['HS256'],
                                     signers: [{ algorithm: 'HS256', key: secret_a, kid: 'a' }],
                                     policy: :all,
                                     crit: ['custom'])
      expect(result).to be_verified
    end

    it 'rejects crit parameters that are not present in the header' do
      signed = described_class.sign(payload, [
        { algorithm: 'HS256', key: secret_a, kid: 'a', protected_header: { 'crit' => ['custom'] } }
      ])

      result = described_class.verify(signed, algorithms: ['HS256'],
                                     signers: [{ algorithm: 'HS256', key: secret_a, kid: 'a' }],
                                     policy: :all,
                                     crit: ['custom'])
      expect(result.signatures[0].error).to match(/not present in the header/)
    end

    it 'does not count the same key twice as independent signers' do
      signed = described_class.sign(payload, [
        { algorithm: 'HS256', key: secret_a, kid: 'a' },
        { algorithm: 'HS256', key: secret_a, kid: 'a-copy' }
      ])

      result = described_class.verify(signed, algorithms: ['HS256'], keys: [secret_a, secret_b], policy: 2)
      expect(result).not_to be_verified
      expect(result.error).to match(/At least 2 independent signer/)
    end

    it 'satisfies a numeric threshold with distinct keys' do
      result = described_class.verify(jws, algorithms: ['HS256'], keys: [secret_a, secret_b], policy: 2)
      expect(result).to be_verified
    end

    it 'supports an any policy with a single valid signature' do
      tampered = deep_duplicate(jws)
      tampered['signatures'][1]['signature'] = 'invalid'

      result = described_class.verify(tampered, algorithms: ['HS256'], keys: [secret_a, secret_b], policy: :any)
      expect(result).to be_verified
    end

    it 'supports a threshold given as a hash' do
      result = described_class.verify(jws, algorithms: ['HS256'], keys: [secret_a, secret_b], policy: { threshold: 1 })
      expect(result).to be_verified
    end

    it 'returns unverified payload even when the policy is not met' do
      tampered = deep_duplicate(jws)
      tampered['signatures'][1]['signature'] = tampered['signatures'][0]['signature']

      result = described_class.verify(tampered, algorithms: ['HS256'], signers: verifiers, policy: :all)
      expect(result.unverified_payload).to eq(payload)
      expect { result.payload }.to raise_error(JWT::TokenError)
    end

    it 'rejects a malformed structure' do
      expect { described_class.verify('not-json', algorithms: ['HS256'], keys: [secret_a]) }
        .to raise_error(JWT::MalformedTokenError)
      expect { described_class.verify({ 'signatures' => [] }, algorithms: ['HS256'], keys: [secret_a]) }
        .to raise_error(JWT::MalformedTokenError)
    end

    it 'supports a keyfinder block' do
      keys = { 'a' => secret_a, 'b' => secret_b }
      result = described_class.verify(jws,
                                     algorithms: ['HS256'],
                                     keyfinder: ->(headers) { keys[headers['kid']] },
                                     policy: 2)
      expect(result).to be_verified
    end

    it 'does not match a signature to a signer with a different kid' do
      result = described_class.verify(jws, algorithms: ['HS256'],
                                      signers: [{ algorithm: 'HS256', key: secret_a, kid: 'other' },
                                                { algorithm: 'HS256', key: secret_b, kid: 'b' }],
                                      policy: :all)
      expect(result).not_to be_verified
      expect(result.signatures[0].error).to match(/No verification key available/)
    end

    it 'fails claim verification with expired payload' do
      expired = described_class.sign({ 'sub' => '42', 'exp' => Time.now.to_i - 100 }, signers)

      result = described_class.verify(expired, algorithms: ['HS256'], signers: verifiers, policy: :all)
      expect(result).not_to be_verified
      expect(result.error).to match(/expired/)
    end
  end

  describe '.decode' do
    let(:jws) { described_class.sign(payload, signers) }

    it 'returns the claims and a verified header when the policy passes' do
      decoded_payload, header = described_class.decode(jws, algorithms: ['HS256'], signers: verifiers, policy: :all)
      expect(decoded_payload).to eq(payload)
      expect(header['alg']).to eq('HS256')
    end

    it 'raises when the policy is not satisfied' do
      tampered = deep_duplicate(jws)
      tampered['signatures'][1]['signature'] = tampered['signatures'][0]['signature']

      expect { described_class.decode(tampered, algorithms: ['HS256'], signers: verifiers, policy: :all) }
        .to raise_error(JWT::VerificationError, /Expected all 2 signer/)
    end

    it 'raises when no algorithm whitelist is provided' do
      expect { described_class.decode(jws, signers: verifiers) }
        .to raise_error(JWT::IncorrectAlgorithm)
    end
  end
end
