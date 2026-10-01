# frozen_string_literal: true

RSpec.describe JWT::ValidationProfile do
  let(:now) { Time.now.to_i }
  let(:clock) { -> { Time.at(now) } }

  let(:access_profile) do
    described_class.new(
      name: 'access',
      typ: 'at+JWT',
      issuer: 'https://id.example.com',
      audience: 'api.example.com',
      required_claims: %w[sub iat exp],
      forbidden_claims: %w[pwr],
      max_lifetime: 900,
      leeway: 5,
      clock: clock
    )
  end

  let(:reset_profile) do
    described_class.new(
      name: 'password-reset',
      typ: 'reset+JWT',
      issuer: 'https://id.example.com',
      audience: 'id.example.com',
      required_claims: %w[sub iat exp pwr],
      forbidden_claims: %w[scope],
      max_lifetime: 1800,
      leeway: 5,
      clock: clock
    )
  end

  let(:valid_access_payload) do
    {
      'sub' => 'user-42',
      'iat' => now,
      'exp' => now + 300,
      'iss' => 'https://id.example.com',
      'aud' => 'api.example.com'
    }
  end

  let(:valid_reset_payload) do
    {
      'sub' => 'user-42',
      'iat' => now,
      'exp' => now + 600,
      'pwr' => 'reset-token',
      'iss' => 'https://id.example.com',
      'aud' => 'id.example.com'
    }
  end

  describe 'construction' do
    it 'accepts the documented options' do
      profile = described_class.new(
        name: :test,
        typ: %w[a b],
        issuer: %w[issuer-a issuer-b],
        audience: %w[aud-a],
        required_claims: %w[sub],
        forbidden_claims: %w[admin],
        max_lifetime: 60,
        leeway: 2,
        clock: clock
      )
      expect(profile.name).to eq(:test)
      expect(profile.typ).to eq(%w[a b])
      expect(profile.issuer).to eq(%w[issuer-a issuer-b])
      expect(profile.audience).to eq(%w[aud-a])
      expect(profile.required_claims).to eq(%w[sub])
      expect(profile.forbidden_claims).to eq(%w[admin])
      expect(profile.max_lifetime).to eq(60)
      expect(profile.leeway).to eq(2)
    end

    it 'accepts the iss and aud aliases' do
      profile = described_class.new(iss: 'me', aud: 'you')
      expect(profile.issuer).to eq(%w[me])
      expect(profile.audience).to eq(%w[you])
    end

    it 'rejects both issuer aliases being given' do
      expect { described_class.new(issuer: 'a', iss: 'b') }.to raise_error(ArgumentError, /not both/)
    end

    it 'rejects both audience aliases being given' do
      expect { described_class.new(audience: 'a', aud: 'b') }.to raise_error(ArgumentError, /not both/)
    end

    it 'rejects a non numeric max_lifetime' do
      expect { described_class.new(max_lifetime: '60') }.to raise_error(ArgumentError, /Integer/)
    end

    it 'rejects a negative max_lifetime' do
      expect { described_class.new(max_lifetime: -1) }.to raise_error(ArgumentError)
    end

    it 'rejects a negative leeway' do
      expect { described_class.new(leeway: -1) }.to raise_error(ArgumentError)
    end

    it 'rejects required_claims that are not an Array' do
      expect { described_class.new(required_claims: 'sub') }.to raise_error(ArgumentError, /Array/)
    end

    it 'rejects a clock that is not callable' do
      expect { described_class.new(clock: Time.now) }.to raise_error(ArgumentError, /#call/)
    end

    it 'rejects non callable custom rules' do
      expect { described_class.new(rules: { bad: 'nope' }) }.to raise_error(ArgumentError, /#call/)
    end

    it 'rejects rules that are neither Array nor Hash' do
      expect { described_class.new(rules: 'nope') }.to raise_error(ArgumentError)
    end
  end

  describe 'immutability' do
    it 'is frozen after construction' do
      expect(access_profile).to be_frozen
    end

    it 'freezes its typ values' do
      expect { access_profile.typ << 'other' }.to raise_error(FrozenError)
    end

    it 'freezes its required claims' do
      expect { access_profile.required_claims << 'scope' }.to raise_error(FrozenError)
    end

    it 'freezes its custom rules' do
      profile = described_class.new(rules: { a: ->(p, h) { [p, h] } })
      expect { profile.instance_variable_get(:@custom_rules) << [:b, -> {}] }.to raise_error(FrozenError)
    end

    it 'does not freeze a caller supplied clock callable' do
      expect(clock).not_to be_frozen
    end
  end

  describe '#verify!' do
    it 'passes a valid access token' do
      expect(access_profile.verify!(valid_access_payload, { 'typ' => 'at+JWT' })).to be_nil
    end

    it 'passes a valid reset token' do
      expect(reset_profile.verify!(valid_reset_payload, { 'typ' => 'reset+JWT' })).to be_nil
    end

    it 'rejects a reset token against the access profile' do
      expect { access_profile.verify!(valid_reset_payload, { 'typ' => 'reset+JWT' }) }
        .to raise_error(JWT::ProfileViolation) do |error|
        expect(error.message).to include("'access'")
        expect(error.message).to include('typ:')
        expect(error.message).to include('aud:')
        expect(error.message).to include('forbidden_claims:')
        expect(error.message).to include('pwr')
        # error reporting never includes the verification key
        expect(error.message).not_to include('secret')
      end
    end

    it 'rejects an access token against the reset profile' do
      expect { reset_profile.verify!(valid_access_payload, { 'typ' => 'at+JWT' }) }
        .to raise_error(JWT::ProfileViolation) do |error|
        expect(error.message).to include('typ:')
        expect(error.message).to include('aud:')
        expect(error.message).to include('required_claims:')
        expect(error.message).to include('pwr')
      end
    end

    it 'collects every violated rule in a single error' do
      payload = { 'iat' => now - 10_000, 'exp' => now - 5_000 }
      begin
        reset_profile.verify!(payload, { 'typ' => 'wrong' })
      rescue JWT::ProfileViolation => e
        rules = e.message.scan(/(\w+):/).flatten
        aggregate_failures do
          expect(rules).to include('typ', 'iss', 'aud', 'required_claims', 'exp', 'max_lifetime')
        end
      else
        raise 'expected ProfileViolation'
      end
    end
  end

  describe '#violations' do
    it 'returns an empty array for a valid token' do
      violations = access_profile.violations(valid_access_payload, { 'typ' => 'at+JWT' })
      expect(violations).to eq([])
    end

    it 'returns RuleViolation objects naming the rule and message' do
      violations = access_profile.violations({}, {})
      expect(violations).to all(be_a(JWT::ValidationProfile::RuleViolation))
      rules = violations.map(&:rule)
      expect(rules).to include(:typ, :iss, :aud, :required_claims)
    end

    it 'accepts a token-like object responding to payload and header' do
      token = SpecSupport::Token.new(payload: valid_access_payload, header: { 'typ' => 'at+JWT' })
      expect(access_profile.violations(token)).to eq([])
    end
  end

  describe '#valid?' do
    it 'is true for a conforming token' do
      expect(access_profile.valid?(valid_access_payload, { 'typ' => 'at+JWT' })).to be(true)
    end

    it 'is false for a non conforming token' do
      expect(access_profile.valid?({}, {})).to be(false)
    end

    it 'defaults the header to an empty hash' do
      expect(access_profile.valid?(valid_access_payload)).to be(false)
    end
  end

  describe 'typ rule' do
    let(:profile) { described_class.new(typ: 'JWT') }

    it 'accepts an exact match' do
      expect(profile.valid?({}, { 'typ' => 'JWT' })).to be(true)
    end

    it 'does not normalize the typ value' do
      expect(profile.valid?({}, { 'typ' => 'jwt' })).to be(false)
    end

    it 'rejects a missing typ header' do
      violations = profile.violations({}, {})
      expect(violations.map(&:rule)).to eq([:typ])
    end

    it 'accepts one of several typ values' do
      multi = described_class.new(typ: %w[at+JWT reset+JWT])
      expect(multi.valid?({}, { 'typ' => 'reset+JWT' })).to be(true)
      expect(multi.valid?({}, { 'typ' => 'other' })).to be(false)
    end

    it 'is not enforced when no typ is configured' do
      expect(described_class.new.valid?({}, {})).to be(true)
    end
  end

  describe 'issuer rule' do
    let(:profile) { described_class.new(issuer: 'issuer-a') }

    it 'accepts a matching issuer' do
      expect(profile.valid?({ 'iss' => 'issuer-a' }, {})).to be(true)
    end

    it 'rejects a non matching issuer' do
      expect(profile.violations({ 'iss' => 'issuer-b' }, {}).map(&:rule)).to eq([:iss])
    end

    it 'rejects a missing issuer' do
      expect(profile.violations({}, {}).map(&:rule)).to eq([:iss])
    end

    it 'accepts any of the configured issuers' do
      multi = described_class.new(issuer: %w[a b])
      expect(multi.valid?({ 'iss' => 'b' }, {})).to be(true)
    end
  end

  describe 'audience rule' do
    let(:profile) { described_class.new(audience: 'aud-a') }

    it 'accepts a matching audience' do
      expect(profile.valid?({ 'aud' => 'aud-a' }, {})).to be(true)
    end

    it 'accepts an audience array containing an expected value' do
      expect(profile.valid?({ 'aud' => %w[other aud-a] }, {})).to be(true)
    end

    it 'rejects a non matching audience' do
      expect(profile.violations({ 'aud' => 'aud-b' }, {}).map(&:rule)).to eq([:aud])
    end
  end

  describe 'required and forbidden claims' do
    let(:profile) do
      described_class.new(required_claims: %w[sub], forbidden_claims: %w[admin], clock: clock)
    end

    it 'passes when required claims are present and forbidden are absent' do
      expect(profile.valid?({ 'sub' => 'u' }, {})).to be(true)
    end

    it 'fails when a required claim is missing' do
      expect(profile.violations({}, {}).map(&:rule)).to eq([:required_claims])
    end

    it 'fails when a forbidden claim is present' do
      violations = profile.violations({ 'sub' => 'u', 'admin' => true }, {})
      expect(violations.map(&:rule)).to eq([:forbidden_claims])
      expect(violations.first.message).to include('admin')
    end

    it 'does not let leeway relax structural rules' do
      tolerant = described_class.new(required_claims: %w[sub], forbidden_claims: %w[admin], leeway: 3600)
      expect(tolerant.valid?({ 'admin' => true }, {})).to be(false)
    end
  end

  describe 'time based rules' do
    it 'rejects an expired token' do
      profile = described_class.new(clock: clock)
      expect(profile.violations({ 'exp' => now - 1 }, {}).map(&:rule)).to eq([:exp])
    end

    it 'treats exp equal to now as expired' do
      profile = described_class.new(clock: clock)
      expect(profile.valid?({ 'exp' => now }, {})).to be(false)
    end

    it 'leeway widens the exp window' do
      profile = described_class.new(clock: clock, leeway: 10)
      expect(profile.valid?({ 'exp' => now - 5 }, {})).to be(true)
      expect(profile.valid?({ 'exp' => now - 50 }, {})).to be(false)
    end

    it 'rejects an immature nbf claim' do
      profile = described_class.new(clock: clock)
      expect(profile.violations({ 'nbf' => now + 10 }, {}).map(&:rule)).to eq([:nbf])
    end

    it 'leeway widens the nbf window' do
      profile = described_class.new(clock: clock, leeway: 10)
      expect(profile.valid?({ 'nbf' => now + 5 }, {})).to be(true)
    end

    it 'rejects an iat claim in the future' do
      profile = described_class.new(clock: clock)
      expect(profile.violations({ 'iat' => now + 100 }, {}).map(&:rule)).to eq([:iat])
    end

    it 'ignores time claims that are absent' do
      profile = described_class.new(clock: clock)
      expect(profile.violations({}, {})).to eq([])
    end

    it 'rejects non numeric time claims' do
      profile = described_class.new(clock: clock)
      expect(profile.valid?({ 'exp' => 'soon' }, {})).to be(false)
      expect(profile.valid?({ 'nbf' => 'later' }, {})).to be(false)
      expect(profile.valid?({ 'iat' => 'yesterday' }, {})).to be(false)
    end
  end

  describe 'max_lifetime rule' do
    let(:profile) { described_class.new(max_lifetime: 600, leeway: 0, clock: clock) }

    it 'accepts a token within the lifetime' do
      expect(profile.valid?({ 'iat' => now, 'exp' => now + 600 }, {})).to be(true)
    end

    it 'rejects a token exceeding the lifetime' do
      expect(profile.violations({ 'iat' => now, 'exp' => now + 601 }, {}).map(&:rule)).to eq([:max_lifetime])
    end

    it 'includes leeway in the allowed lifetime' do
      tolerant = described_class.new(max_lifetime: 600, leeway: 10, clock: clock)
      expect(tolerant.valid?({ 'iat' => now, 'exp' => now + 605 }, {})).to be(true)
      expect(tolerant.valid?({ 'iat' => now, 'exp' => now + 700 }, {})).to be(false)
    end

    it 'requires both iat and exp' do
      violations = profile.violations({ 'iat' => now }, {})
      expect(violations.map(&:rule)).to eq([:max_lifetime])
      expect(violations.first.message).to include('exp')
    end

    it 'rejects exp before iat' do
      violations = profile.violations({ 'iat' => now, 'exp' => now - 1 }, {})
      expect(violations.map(&:rule)).to include(:max_lifetime, :exp)
    end

    it 'rejects non numeric iat or exp' do
      expect(profile.valid?({ 'iat' => 'a', 'exp' => 'b' }, {})).to be(false)
    end
  end

  describe 'custom rules' do
    it 'runs a named rule from a hash' do
      profile = described_class.new(rules: { numeric_subject: ->(payload, _header) { payload['sub'].is_a?(Numeric) } }, clock: clock)
      expect(profile.valid?({ 'sub' => 1 }, {})).to be(true)
      violations = profile.violations({ 'sub' => 'x' }, {})
      expect(violations.map(&:rule)).to eq([:numeric_subject])
    end

    it 'passes payload and header to the rule' do
      seen = nil
      profile = described_class.new(rules: { echo: ->(payload, header) { seen = [payload, header]; true } })
      profile.verify!({ 'a' => 1 }, { 'b' => 2 })
      expect(seen).to eq([{ 'a' => 1 }, { 'b' => 2 }])
    end

    it 'supports a bare callable rule named custom' do
      profile = described_class.new(rules: [->(_payload, _header) { false }])
      expect(profile.violations({}, {}).map(&:rule)).to eq([:custom])
    end

    it 'supports a [name, callable] pair inside an array' do
      profile = described_class.new(rules: [[:pair, ->(_p, _h) { nil }]])
      expect(profile.violations({}, {}).map(&:rule)).to eq([:pair])
    end

    it 'uses a returned failure string as the violation message' do
      profile = described_class.new(rules: { check: ->(_p, _h) { 'nope' } })
      expect(profile.violations({}, {}).first.message).to eq('nope')
    end

    it 'uses a default message for a blank failure string' do
      profile = described_class.new(rules: { check: ->(_p, _h) { '   ' } })
      expect(profile.violations({}, {}).first.message).to include('Custom validation rule failed')
    end

    it 'accepts a raised ClaimValidationError as the violation message' do
      profile = described_class.new(
        rules: { check: ->(_p, _h) { raise JWT::InvalidPayload, 'explicit failure' } }
      )
      expect(profile.violations({}, {}).first.message).to eq('explicit failure')
    end

    it 'accepts a truthy non string return value' do
      profile = described_class.new(rules: { check: ->(_p, _h) { 42 } })
      expect(profile.valid?({}, {})).to be(true)
    end
  end

  describe 'clock' do
    it 'uses the injected clock for time based checks' do
      fixed = described_class.new(clock: -> { Time.at(1_000) })
      expect(fixed.valid?({ 'exp' => 2_000 }, {})).to be(true)
      expect(fixed.valid?({ 'exp' => 500 }, {})).to be(false)
    end

    it 'defaults to the system clock' do
      profile = described_class.new
      expect(profile.valid?({ 'exp' => Time.now.to_i + 100 }, {})).to be(true)
    end
  end

  describe 'malformed inputs' do
    it 'reports required claim violations for a non Hash payload' do
      profile = described_class.new(required_claims: %w[sub], clock: clock)
      violations = profile.violations(['unexpected'], {})
      expect(violations.map(&:rule)).to eq([:required_claims])
    end

    it 'does not raise on a nil payload' do
      expect { described_class.new.violations(nil, {}) }.not_to raise_error
    end

    it 'rejects a single non token object without a payload method' do
      expect { access_profile.violations(:not_a_token) }.to raise_error(ArgumentError, /#payload/)
    end

    it 'accepts a JWT::Token object directly' do
      token = JWT::Token.new(payload: valid_access_payload, header: { 'typ' => 'at+JWT' })
      expect(access_profile.valid?(token)).to be(true)
    end
  end

  describe 'integration with JWT.decode' do
    let(:key) { 'shared-signing-secret' }
    let(:algorithm) { 'HS256' }

    def encode_jwt(payload, header)
      JWT.encode(payload, key, algorithm, header)
    end

    it 'accepts a valid token under the server selected profile' do
      jwt = encode_jwt(valid_reset_payload, { 'typ' => 'reset+JWT' })
      payload, header = JWT.decode(jwt, key, true, algorithms: [algorithm], profile: reset_profile)
      expect(payload['sub']).to eq('user-42')
      expect(header['typ']).to eq('reset+JWT')
    end

    it 'rejects a reset token under the access profile even with a valid signature' do
      jwt = encode_jwt(valid_reset_payload, { 'typ' => 'reset+JWT' })
      expect { JWT.decode(jwt, key, true, algorithms: [algorithm], profile: access_profile) }
        .to raise_error(JWT::ProfileViolation, /typ/)
    end

    it 'verifies the signature before applying profile rules' do
      jwt = encode_jwt(valid_reset_payload, { 'typ' => 'reset+JWT' })
      expect { JWT.decode(jwt, 'wrong-key', true, algorithms: [algorithm], profile: reset_profile) }
        .to raise_error(JWT::VerificationError)
    end

    it 'does not apply profile rules when signature verification is disabled' do
      jwt = encode_jwt({ 'nothing' => true }, { 'typ' => 'reset+JWT' })
      payload, = JWT.decode(jwt, nil, false, profile: reset_profile)
      expect(payload).to eq({ 'nothing' => true })
    end

    it 'does not let token side options disable profile rules' do
      payload = valid_reset_payload.merge('exp' => now - 10_000)
      jwt = encode_jwt(payload, { 'typ' => 'reset+JWT' })
      expect do
        JWT.decode(jwt, key, true, algorithms: [algorithm], profile: reset_profile, verify_expiration: false)
      end.to raise_error(JWT::ProfileViolation, /exp/)
    end

    it 'raises ArgumentError when the profile does not respond to verify!' do
      jwt = encode_jwt(valid_reset_payload, { 'typ' => 'reset+JWT' })
      expect { JWT.decode(jwt, key, true, algorithms: [algorithm], profile: :not_a_profile) }
        .to raise_error(ArgumentError, /profile/)
    end

    it 'keeps legacy claim verification when no profile is given' do
      jwt = encode_jwt({ 'exp' => now - 10 }, {})
      expect { JWT.decode(jwt, key, true, algorithms: [algorithm]) }.to raise_error(JWT::ExpiredSignature)
    end
  end

  describe 'integration with JWT::EncodedToken' do
    let(:key) { 'shared-signing-secret' }
    let(:jwt) { JWT.encode(valid_reset_payload, key, 'HS256', { 'typ' => 'reset+JWT' }) }
    let(:token) { JWT::EncodedToken.new(jwt) }

    it 'verifies a token against a profile through verify!' do
      token.verify!(signature: { algorithm: 'HS256', key: key }, profile: reset_profile)
      expect(token.payload['sub']).to eq('user-42')
    end

    it 'raises ProfileViolation through verify!' do
      expect { token.verify!(signature: { algorithm: 'HS256', key: key }, profile: access_profile) }
        .to raise_error(JWT::ProfileViolation)
    end

    it 'reports validity against a profile' do
      expect(token.valid?(signature: { algorithm: 'HS256', key: key }, profile: reset_profile)).to be(true)
      expect(token.valid?(signature: { algorithm: 'HS256', key: key }, profile: access_profile)).to be(false)
    end

    it 'checks the signature before the profile' do
      expect { token.verify!(signature: { algorithm: 'HS256', key: 'wrong' }, profile: reset_profile) }
        .to raise_error(JWT::VerificationError)
    end

    it 'exposes verify_profile! directly' do
      token.verify_signature!(algorithm: 'HS256', key: key)
      token.verify_profile!(reset_profile)
      expect(token.payload['sub']).to eq('user-42')
    end
  end
end
