# frozen_string_literal: true

RSpec.describe JWT::OIDC::Profile do
  let(:key) { test_pkey('rsa-2048-private.pem') }
  let(:public_key) { test_pkey('rsa-2048-public.pem') }
  let(:client_id) { 'client-123' }
  let(:nonce) { 'nonce-abc' }
  let(:code_one) { 'authorization-code-one' }
  let(:code_two) { 'authorization-code-two' }
  let(:access_token_one) { 'access-token-one' }
  let(:access_token_two) { 'access-token-two' }

  def hash_claim(value, digest_algorithm)
    digest = OpenSSL::Digest.digest(digest_algorithm, value)
    JWT::Base64.url_encode(digest.byteslice(0, digest.bytesize / 2))
  end

  def signed_id_token(flow, code:, access_token:, algorithm: 'RS256', audience: client_id, **extra_claims)
    digest_algorithm = described_class::HASH_ALGORITHMS.fetch(algorithm)
    payload = {
      'iss' => 'https://idp.example',
      'sub' => 'user-1',
      'aud' => audience,
      'nonce' => nonce
    }.merge(extra_claims)

    payload['c_hash'] = hash_claim(code, digest_algorithm) if code
    payload['at_hash'] = hash_claim(access_token, digest_algorithm) if access_token

    JWT::Token
      .new(payload: payload)
      .tap { |token| token.sign!(key: key, algorithm: algorithm) }
      .jwt
  end

  def verify(id_token, flow:, code: nil, access_token: nil, **options)
    token = JWT::EncodedToken.new(id_token)
    token.verify_signature!(algorithm: 'RS256', key: public_key)
    described_class.new(
      flow,
      code: code,
      access_token: access_token,
      client_id: client_id,
      **options
    ).verify!(context: JWT::EncodedToken::ClaimsContext.new(token))
  end

  shared_examples 'a response binding failure' do |claim, flow|
    it 'does not bind the ID token to the exchanged response value' do
      first_id_token = signed_id_token(
        flow,
        code: flow == :hybrid ? code_one : nil,
        access_token: access_token_one
      )
      second_id_token = signed_id_token(
        flow,
        code: flow == :hybrid ? code_two : nil,
        access_token: access_token_two
      )

      verify(
        first_id_token,
        flow: flow,
        code: flow == :hybrid ? code_one : nil,
        access_token: access_token_one
      )
      verify(
        second_id_token,
        flow: flow,
        code: flow == :hybrid ? code_two : nil,
        access_token: access_token_two
      )

      expect do
        verify(
          first_id_token,
          flow: flow,
          code: flow == :hybrid ? code_two : nil,
          access_token: flow == :implicit ? access_token_two : access_token_one
        )
      end.to raise_error(claim)

      expect do
        verify(
          second_id_token,
          flow: flow,
          code: flow == :hybrid ? code_one : nil,
          access_token: flow == :implicit ? access_token_one : access_token_two
        )
      end.to raise_error(claim)
    end
  end

  describe 'code response' do
    it 'accepts an ID token without code and access token hashes' do
      id_token = JWT::Token.new(payload: { 'aud' => client_id }).tap do |token|
        token.sign!(key: key, algorithm: 'RS256')
      end.jwt

      expect(verify(id_token, flow: :code)).to be_nil
    end

    it 'verifies a c_hash or at_hash when the profile is given that response value' do
      id_token = signed_id_token(
        :code,
        code: code_one,
        access_token: access_token_one
      )

      expect(verify(id_token, flow: :code, code: code_one, access_token: access_token_one)).to be_nil
      expect { verify(id_token, flow: :code, code: code_two, access_token: access_token_one) }.to raise_error(JWT::InvalidCHashError)
      expect { verify(id_token, flow: :code, code: code_one, access_token: access_token_two) }.to raise_error(JWT::InvalidAtHashError)
    end
  end

  describe 'implicit response' do
    it 'accepts a legal authorization response' do
      id_token = signed_id_token(:implicit, code: nil, access_token: access_token_one)

      expect(verify(id_token, flow: :implicit, access_token: access_token_one, nonce: nonce)).to be_nil
    end

    it 'requires nonce and access token hash' do
      id_token = signed_id_token(:implicit, code: nil, access_token: access_token_one)

      expect { verify(id_token, flow: :implicit, access_token: access_token_one, nonce: 'other') }.to raise_error(JWT::InvalidNonceError)
      token = JWT::EncodedToken.new(JWT::Token.new(payload: { 'aud' => client_id }).tap { |t| t.sign!(key: key, algorithm: 'RS256') }.jwt)
      profile = described_class.new(:implicit, algorithm: 'RS256', client_id: client_id, access_token: access_token_one)
      expect { profile.verify!(context: JWT::EncodedToken::ClaimsContext.new(token)) }.to raise_error(JWT::MissingRequiredClaim, 'Missing required claim nonce')
    end

    it 'rejects a non-string nonce' do
      id_token = JWT::Token.new(payload: { 'aud' => client_id, 'nonce' => 123 }).tap do |token|
        token.sign!(key: key, algorithm: 'RS256')
      end.jwt

      expect { verify(id_token, flow: :implicit, access_token: access_token_one) }.to raise_error(JWT::InvalidNonceError)
    end

    it 'rejects c_hash because implicit responses do not return a code' do
      id_token = signed_id_token(
        :implicit,
        code: code_one,
        access_token: access_token_one
      )

      expect { verify(id_token, flow: :implicit, access_token: access_token_one, nonce: nonce) }.to raise_error(JWT::InvalidCHashError)
    end

    include_examples 'a response binding failure', JWT::InvalidAtHashError, :implicit
  end

  describe 'hybrid response' do
    it 'accepts a legal authorization response' do
      id_token = signed_id_token(
        :hybrid,
        code: code_one,
        access_token: access_token_one
      )

      expect(verify(id_token, flow: :hybrid, code: code_one, access_token: access_token_one, nonce: nonce)).to be_nil
    end

    it 'requires nonce and c_hash' do
      id_token = signed_id_token(:hybrid, code: code_one, access_token: nil)

      expect { verify(id_token, flow: :hybrid, code: code_one, nonce: 'other') }.to raise_error(JWT::InvalidNonceError)

      token = JWT::EncodedToken.new(JWT::Token.new(payload: { 'nonce' => nonce, 'at_hash' => 'unused', 'aud' => client_id }).tap { |t| t.sign!(key: key, algorithm: 'RS256') }.jwt)
      profile = described_class.new(:hybrid, algorithm: 'RS256', code: code_one, client_id: client_id)
      expect { profile.verify!(context: JWT::EncodedToken::ClaimsContext.new(token)) }.to raise_error(JWT::MissingRequiredClaim, 'Missing required claim c_hash')
    end

    it 'requires at_hash only when the hybrid response contains an access token' do
      without_access_token = signed_id_token(:hybrid, code: code_one, access_token: nil)
      with_access_token = signed_id_token(:hybrid, code: code_one, access_token: nil)

      expect(verify(without_access_token, flow: :hybrid, code: code_one, nonce: nonce)).to be_nil
      expect { verify(with_access_token, flow: :hybrid, code: code_one, access_token: access_token_one, nonce: nonce) }.to raise_error(JWT::MissingRequiredClaim, 'Missing required claim at_hash')
    end

    include_examples 'a response binding failure', JWT::InvalidCHashError, :hybrid
  end

  describe 'authorized party' do
    it 'requires azp for multiple audiences and checks its value' do
      id_token = signed_id_token(
        :code,
        code: nil,
        access_token: nil,
        audience: [client_id, 'other-aud']
      )

      expect { verify(id_token, flow: :code) }.to raise_error(JWT::InvalidAzpError)

      valid = signed_id_token(
        :code,
        code: nil,
        access_token: nil,
        audience: [client_id, 'other-aud'],
        'azp' => client_id
      )
      invalid = signed_id_token(
        :code,
        code: nil,
        access_token: nil,
        audience: [client_id, 'other-aud'],
        'azp' => 'attacker'
      )

      expect(verify(valid, flow: :code)).to be_nil
      expect { verify(invalid, flow: :code) }.to raise_error(JWT::InvalidAzpError)
    end
  end

  describe 'hash algorithm' do
    it 'requires an explicitly verified JWS algorithm for direct claim verification' do
      id_token = signed_id_token(:hybrid, code: code_one, access_token: nil)
      token = JWT::EncodedToken.new(id_token)
      profile = described_class.new(:hybrid, code: code_one, client_id: client_id, nonce: nonce)

      expect { profile.verify!(context: JWT::EncodedToken::ClaimsContext.new(token)) }.to raise_error(JWT::IncorrectAlgorithm, /verified JWS algorithm/)
    end

    it 'uses the digest corresponding to the verified signing algorithm' do
      id_token = signed_id_token(
        :hybrid,
        code: code_one,
        access_token: nil,
        algorithm: 'RS512'
      )
      token = JWT::EncodedToken.new(id_token)
      token.verify_signature!(algorithm: 'RS512', key: public_key)
      profile = described_class.new(:hybrid, code: code_one, client_id: client_id, nonce: nonce)

      expect(profile.verify!(context: JWT::EncodedToken::ClaimsContext.new(token))).to be_nil
    end

    it 'does not fall back to SHA-256 for an unknown algorithm' do
      token = JWT::EncodedToken.new('eyJhbGciOiJFUzOTk5In0.eyJub25jZSI6Im4ifQ.signature')
      profile = described_class.new(:hybrid, algorithm: 'ES999', code: code_one, client_id: client_id, nonce: nonce)

      expect { profile.verify!(context: JWT::EncodedToken::ClaimsContext.new(token)) }.to raise_error(JWT::IncorrectAlgorithm, /ES999/)
    end
  end

  describe 'JWT.decode integration' do
    it 'passes the verified algorithm to the OIDC profile' do
      id_token = signed_id_token(:hybrid, code: code_one, access_token: nil)

      decoded_payload, header = JWT.decode(
        id_token,
        public_key,
        true,
        algorithm: 'RS256',
        verify_expiration: false,
        oidc: { flow: :hybrid, code: code_one, client_id: client_id, nonce: nonce }
      )

      expect(header).to include('alg' => 'RS256')
      expect(decoded_payload).to include('nonce' => nonce)
    end
  end
end
