# frozen_string_literal: true

RSpec.describe JWT::ValidationProfile do
  let(:now) { Time.at(1_000_000) }
  let(:clock) { -> { now } }

  let(:access_profile) do
    described_class.new(
      name: :access,
      typ: 'access',
      issuer: 'id.example.com',
      audience: 'api.example.com',
      required_claims: %w[sub iat exp],
      forbidden_claims: %w[reset_purpose],
      max_lifetime: 900,
      leeway: 5,
      clock: clock
    )
  end

  let(:reset_profile) do
    described_class.new(
      name: :password_reset,
      typ: 'password_reset',
      issuer: 'id.example.com',
      audience: 'id.example.com',
      required_claims: %w[sub iat exp reset_purpose],
      forbidden_claims: %w[scope],
      max_lifetime: 300,
      clock: clock
    )
  end

  let(:access_payload) do
    {
      'iss' => 'id.example.com',
      'aud' => 'api.example.com',
      'sub' => 'user-1',
      'iat' => now.to_i,
      'exp' => now.to_i + 600,
      'scope' => 'read'
    }
  end

  let(:reset_payload) do
    {
      'iss' => 'id.example.com',
      'aud' => 'id.example.com',
      'sub' => 'user-1',
      'iat' => now.to_i,
      'exp' => now.to_i + 200,
      'reset_purpose' => 'password'
    }
  end

  def token(payload, header)
    SpecSupport::Token.new(payload: payload, header: header)
  end

  describe '#verify! and #valid?' do
    it 'accepts an access token presented to the access profile' do
      access_profile.verify!(token(access_payload, { 'typ' => 'access' }))
      expect(access_profile).to be_valid(token(access_payload, { 'typ' => 'access' }))
    end

    it 'accepts a reset token presented to the reset profile' do
      reset_profile.verify!(token(reset_payload, { 'typ' => 'password_reset' }))
    end

    it 'rejects a perfectly valid reset token presented to the access profile' do
      violations = access_profile.violations(token(reset_payload, { 'typ' => 'password_reset' }))
      expect(violations.map(&:rule)).to contain_exactly(:typ, :aud, :forbidden)
      expect(access_profile).not_to be_valid(token(reset_payload, { 'typ' => 'password_reset' }))
    end

    it 'rejects an access token presented to the reset profile' do
      violations = reset_profile.violations(token(access_payload, { 'typ' => 'access' }))
      expect(violations.map(&:rule)).to contain_exactly(:typ, :aud, :required, :forbidden, :max_lifetime)
    end

    it 'raises a single ProfileViolation naming every broken rule' do
      expect do
        access_profile.verify!(token(reset_payload, { 'typ' => 'password_reset' }))
      end.to raise_error(JWT::ProfileViolation) do |error|
        expect(error.message).to include("Validation profile 'access' violated")
        expect(error.message).to include('- typ:')
        expect(error.message).to include('- aud:')
        expect(error.message).to include('- forbidden:')
        expect(error.violations.size).to eq(3)
      end
    end

    it 'omits the profile name from the error message when none was given' do
      unnamed = described_class.new(typ: 'access', clock: clock, verify_expiration: false,
                                   verify_not_before: false, verify_issued_at: false, verify_numeric: false)
      expect { unnamed.verify!(token({}, { 'typ' => 'reset' })) }
        .to raise_error(JWT::ProfileViolation, /\AValidation profile violated:/)
    end
  end

  describe 'bound rules' do
    it 'rejects an unknown issuer' do
      payload = access_payload.merge('iss' => 'attacker.example')
      expect(access_profile.violations(token(payload, { 'typ' => 'access' })).map(&:rule)).to include(:iss)
    end

    it 'accepts any of several configured issuers and types' do
      profile = described_class.new(
        typ: %w[access refresh], issuer: %w[id.example.com id2.example.com],
        clock: clock, verify_expiration: false, verify_not_before: false, verify_issued_at: false
      )
      profile.verify!(token({ 'iss' => 'id2.example.com' }, { 'typ' => 'refresh' }))
    end

    it 'reports missing required claims' do
      payload = access_payload.reject { |key| key == 'sub' }
      violations = access_profile.violations(token(payload, { 'typ' => 'access' }))
      expect(violations).to include(have_attributes(rule: :required, message: 'Missing required claim sub'))
    end

    it 'reports a lifetime longer than allowed independently of the clock' do
      payload = access_payload.merge('iat' => now.to_i - 10_000, 'exp' => now.to_i)
      violation = access_profile.violations(token(payload, { 'typ' => 'access' })).find { |v| v.rule == :max_lifetime }
      expect(violation.message).to include('10000 seconds').and include('900 seconds')
    end

    it 'rejects expired tokens using the injected clock and leeway' do
      payload = access_payload.merge('exp' => now.to_i - 10)
      expect(access_profile).not_to be_valid(token(payload, { 'typ' => 'access' }))

      within_leeway = described_class.new(leeway: 10, clock: clock,
                                          verify_not_before: false, verify_issued_at: false, verify_numeric: false)
      within_leeway.verify!(token(payload.merge('exp' => now.to_i - 5).reject { |k| k == 'iat' }, {}))
    end

    it 'rejects immature tokens honoring leeway' do
      payload = { 'nbf' => now.to_i + 3 }
      strict = described_class.new(leeway: 0, clock: clock,
                                   verify_expiration: false, verify_issued_at: false, verify_numeric: false)
      relaxed = described_class.new(leeway: 5, clock: clock,
                                    verify_expiration: false, verify_issued_at: false, verify_numeric: false)
      expect(strict.violations(token(payload, {})).map(&:rule)).to include(:nbf)
      relaxed.verify!(token(payload, {}))
    end

    it 'rejects an iat in the future' do
      payload = { 'iat' => now.to_i + 100 }
      expect(access_profile.violations(token(payload, {})).map(&:rule)).to include(:iat)
    end

    it 'validates numeric claims by default' do
      payload = access_payload.merge('exp' => 'later')
      expect(access_profile.violations(token(payload, { 'typ' => 'access' })).map(&:rule)).to include(:numeric)
    end

    it 'allows disabling the standard temporal and numeric checks' do
      minimal = described_class.new(
        typ: 'access', clock: clock,
        verify_expiration: false, verify_not_before: false,
        verify_issued_at: false, verify_numeric: false
      )
      minimal.verify!(token({ 'exp' => 'not-a-time' }, { 'typ' => 'access' }))
    end
  end

  describe 'custom rules' do
    let(:deny_admins) do
      stub_const('SpecSupport::DenyAdminsRule', Class.new do
        def verify!(context:)
          raise JWT::ClaimValidationError, 'admins may not use this profile' if context.payload['sub'] == 'admin'
        end
      end).new
    end

    it 'accepts an object responding to verify!(context:)' do
      profile = described_class.new(rules: [deny_admins], clock: clock,
                                    verify_expiration: false, verify_not_before: false,
                                    verify_issued_at: false, verify_numeric: false)
      profile.verify!(token({ 'sub' => 'user' }, {}))
      expect(profile.violations(token({ 'sub' => 'admin' }, {})).first.rule).to eq(:denyadminsrule)
    end

    it 'accepts a callable under an explicit rule name' do
      rule = ->(context) { raise JWT::ClaimValidationError, 'scope missing' unless context.payload.key?('scope') }
      profile = described_class.new(rules: { scope_present: rule }, clock: clock,
                                    verify_expiration: false, verify_not_before: false,
                                    verify_issued_at: false, verify_numeric: false)
      expect(profile.violations(token({}, {})).first).to have_attributes(
        rule: :scope_present, message: 'scope missing'
      )
      profile.verify!(token({ 'scope' => 'read' }, {}))
    end

    it 'passes both payload and header to custom rules' do
      seen = nil
      rule = ->(context) { seen = [context.payload, context.header] }
      profile = described_class.new(rules: { observe: rule }, clock: clock,
                                    verify_expiration: false, verify_not_before: false,
                                    verify_issued_at: false, verify_numeric: false)
      profile.verify!(token({ 'a' => 1 }, { 'typ' => 'access' }))
      expect(seen).to eq([{ 'a' => 1 }, { 'typ' => 'access' }])
    end

    it 'rejects rules that are neither verifiers nor callables at construction' do
      expect { described_class.new(rules: ['nope']) }.to raise_error(ArgumentError, /must respond to verify!/)
    end

    it 'does not swallow non-claim errors raised by custom rules' do
      rule = ->(_context) { raise 'boom' }
      profile = described_class.new(rules: { bad: rule }, clock: clock,
                                    verify_expiration: false, verify_not_before: false,
                                    verify_issued_at: false, verify_numeric: false)
      expect { profile.verify!(token({}, {})) }.to raise_error(RuntimeError, 'boom')
    end
  end

  describe 'immutability' do
    it 'is frozen' do
      expect(access_profile).to be_frozen
    end

    it 'freezes every configured collection' do
      expect { access_profile.expected_typ << 'x' }.to raise_error(FrozenError)
      expect { access_profile.required_claims << 'x' }.to raise_error(FrozenError)
      expect { access_profile.forbidden_claims << 'x' }.to raise_error(FrozenError)
    end

    it 'does not keep a mutable reference to the collections passed in' do
      types = ['access']
      profile = described_class.new(typ: types)
      types << 'reset'
      expect(profile.expected_typ).to eq(['access'])
    end
  end

  describe 'construction validation' do
    it 'rejects a non-positive max lifetime' do
      expect { described_class.new(max_lifetime: 0) }.to raise_error(ArgumentError, /positive/)
    end

    it 'rejects a negative leeway' do
      expect { described_class.new(leeway: -1) }.to raise_error(ArgumentError, /non-negative/)
    end
  end

  describe 'targets' do
    let(:jwt) do
      JWT.encode(reset_payload, 'secret', 'HS256', { 'typ' => 'password_reset' })
    end

    it 'accepts a raw payload hash for payload-only profiles' do
      payload_profile = described_class.new(
        issuer: 'id.example.com', audience: 'id.example.com',
        required_claims: %w[sub iat exp reset_purpose], forbidden_claims: %w[scope],
        max_lifetime: 300, clock: clock
      )
      payload_profile.verify!(reset_payload)
      expect(payload_profile).not_to be_valid(reset_payload.merge('exp' => now.to_i + 999))
    end

    it 'accepts an EncodedToken and reads its unverified payload' do
      encoded = JWT::EncodedToken.new(jwt)
      encoded.verify_signature!(algorithm: 'HS256', key: 'secret')
      reset_profile.verify!(encoded)
    end

    it 'rejects objects that are not tokens or hashes' do
      expect { access_profile.verify!('a.b.c') }.to raise_error(ArgumentError, /token or a payload/)
    end
  end

  describe 'integration with JWT.decode' do
    let(:secret) { 'shared-signing-secret' }

    # JWT.decode runs its own system-clock exp check before the profile, so the
    # encoded token carries real timestamps and the integration profiles use
    # the real system clock instead of the frozen one used above.
    let(:real_now) { Time.now.to_i }
    let(:real_reset_payload) { reset_payload.merge('iat' => real_now, 'exp' => real_now + 200) }
    let(:integration_reset_profile) do
      described_class.new(
        name: :password_reset,
        typ: 'password_reset',
        issuer: 'id.example.com',
        audience: 'id.example.com',
        required_claims: %w[sub iat exp reset_purpose],
        forbidden_claims: %w[scope],
        max_lifetime: 300
      )
    end
    let(:integration_access_profile) do
      described_class.new(
        name: :access,
        typ: 'access',
        issuer: 'id.example.com',
        audience: 'api.example.com',
        required_claims: %w[sub iat exp],
        forbidden_claims: %w[reset_purpose],
        max_lifetime: 900
      )
    end

    let(:reset_jwt) do
      JWT.encode(real_reset_payload, secret, 'HS256', { 'typ' => 'password_reset' })
    end

    it 'accepts the reset token when the server selects the reset profile' do
      payload, = JWT.decode(reset_jwt, secret, true,
                            { algorithms: ['HS256'], validation_profile: integration_reset_profile })
      expect(payload['sub']).to eq('user-1')
    end

    it 'rejects the signature-valid reset token under the access profile' do
      expect do
        JWT.decode(reset_jwt, secret, true,
                   { algorithms: ['HS256'], validation_profile: integration_access_profile })
      end.to raise_error(JWT::ProfileViolation) { |e| expect(e.message).not_to include(secret) }
    end

    it 'never evaluates profile rules for a token with a bad signature' do
      bad = JWT.encode(reset_payload, 'other-secret', 'HS256', { 'typ' => 'password_reset' })
      expect do
        JWT.decode(bad, secret, true,
                   { algorithms: ['HS256'], validation_profile: reset_profile })
      end.to raise_error(JWT::VerificationError)
    end
  end
end
