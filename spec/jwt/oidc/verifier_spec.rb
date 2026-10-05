# frozen_string_literal: true

RSpec.describe JWT::OIDC::Verifier do
  let(:client_id) { 'my-client' }
  let(:nonce) { 'request-nonce' }
  let(:code) { 'authorization-code' }
  let(:access_token) { 'access-token' }

  let(:payload) { { 'iss' => 'https://issuer.example', 'sub' => 'user-1', 'aud' => client_id } }

  def verifier_for(response_type, **overrides)
    described_class.new(**{
      response_type: response_type,
      client_id: client_id,
      nonce: nonce,
      code: code,
      access_token: access_token
    }.merge(overrides))
  end

  describe '#initialize' do
    it 'rejects an unsupported response_type' do
      expect { verifier_for(:token) }.to raise_error(ArgumentError, /Unsupported response_type/)
    end

    it 'requires a client_id' do
      expect { verifier_for(:code, client_id: nil) }.to raise_error(ArgumentError, /client_id/)
    end

    it 'requires a nonce for the implicit response type' do
      expect { verifier_for(:implicit, nonce: nil) }.to raise_error(ArgumentError, /nonce/)
    end

    it 'requires a nonce for the hybrid response type' do
      expect { verifier_for(:hybrid, nonce: nil) }.to raise_error(ArgumentError, /nonce/)
    end

    it 'allows a missing nonce for the code response type' do
      expect(verifier_for(:code, nonce: nil)).to be_a(described_class)
    end
  end

  describe 'nonce verification' do
    it 'passes when the nonce matches' do
      expect(verifier_for(:code).verify!(payload.merge('nonce' => nonce), algorithm: 'RS256')).to be(true)
    end

    it 'fails when the nonce does not match' do
      expect { verifier_for(:code).verify!(payload.merge('nonce' => 'other'), algorithm: 'RS256') }
        .to raise_error(JWT::OIDC::InvalidNonceError, /does not match/)
    end

    it 'fails when an expected nonce is missing from the token' do
      expect { verifier_for(:code).verify!(payload, algorithm: 'RS256') }
        .to raise_error(JWT::OIDC::InvalidNonceError, /missing the nonce/)
    end

    it 'allows a missing nonce claim in the code flow when no nonce was requested' do
      expect(verifier_for(:code, nonce: nil).verify!(payload, algorithm: 'RS256')).to be(true)
    end
  end

  describe 'authorized party verification' do
    it 'allows a single audience without an azp claim' do
      expect(verifier_for(:code, nonce: nil).verify!(payload, algorithm: 'RS256')).to be(true)
    end

    it 'requires an azp claim when the token has multiple audiences' do
      multi_aud = payload.merge('aud' => [client_id, 'other-client'])
      expect { verifier_for(:code, nonce: nil).verify!(multi_aud, algorithm: 'RS256') }
        .to raise_error(JWT::OIDC::InvalidAuthorizedPartyError, /missing the azp/)
    end

    it 'passes when the azp matches the client_id' do
      multi_aud = payload.merge('aud' => [client_id, 'other-client'], 'azp' => client_id)
      expect(verifier_for(:code, nonce: nil).verify!(multi_aud, algorithm: 'RS256')).to be(true)
    end

    it 'fails when the azp does not match the client_id' do
      expect { verifier_for(:code, nonce: nil).verify!(payload.merge('azp' => 'other-client'), algorithm: 'RS256') }
        .to raise_error(JWT::OIDC::InvalidAuthorizedPartyError, /does not match/)
    end
  end

  describe 'token hash verification' do
    let(:c_hash) { JWT::OIDC::HashAlgorithm.hash_token('RS256', code) }
    let(:at_hash) { JWT::OIDC::HashAlgorithm.hash_token('RS256', access_token) }

    it 'requires c_hash in the hybrid flow when a code is returned' do
      expect { verifier_for(:hybrid).verify!(payload.merge('nonce' => nonce), algorithm: 'RS256') }
        .to raise_error(JWT::OIDC::MissingTokenHashError, /c_hash/)
    end

    it 'requires at_hash in the implicit flow when an access token is returned' do
      expect { verifier_for(:implicit).verify!(payload.merge('nonce' => nonce), algorithm: 'RS256') }
        .to raise_error(JWT::OIDC::MissingTokenHashError, /at_hash/)
    end

    it 'allows missing hash claims in the code flow' do
      expect(verifier_for(:code, nonce: nil).verify!(payload, algorithm: 'RS256')).to be(true)
    end

    it 'verifies present hash claims in the code flow' do
      token = payload.merge('c_hash' => c_hash, 'at_hash' => at_hash)
      expect(verifier_for(:code, nonce: nil).verify!(token, algorithm: 'RS256')).to be(true)
    end

    it 'fails when c_hash does not match the code' do
      token = payload.merge('nonce' => nonce, 'c_hash' => c_hash, 'at_hash' => at_hash)
      expect { verifier_for(:hybrid, code: 'swapped-code').verify!(token, algorithm: 'RS256') }
        .to raise_error(JWT::OIDC::InvalidTokenHashError, /c_hash/)
    end

    it 'fails when at_hash does not match the access token' do
      token = payload.merge('nonce' => nonce, 'at_hash' => at_hash)
      expect { verifier_for(:implicit, access_token: 'swapped-token').verify!(token, algorithm: 'RS256') }
        .to raise_error(JWT::OIDC::InvalidTokenHashError, /at_hash/)
    end

    it 'requires the corresponding value when a hash claim is present' do
      token = payload.merge('c_hash' => c_hash)
      expect { verifier_for(:code, nonce: nil, code: nil).verify!(token, algorithm: 'RS256') }
        .to raise_error(ArgumentError, /c_hash/)
    end

    it 'derives the hash algorithm from the verified signature algorithm' do
      token = payload.merge('nonce' => nonce, 'c_hash' => JWT::OIDC::HashAlgorithm.hash_token('ES384', code))
      expect(verifier_for(:hybrid, access_token: nil).verify!(token, algorithm: 'ES384')).to be(true)
    end

    it 'rejects an unknown signature algorithm instead of falling back to SHA-256' do
      token = payload.merge('nonce' => nonce, 'c_hash' => c_hash)
      expect { verifier_for(:hybrid, access_token: nil).verify!(token, algorithm: 'unknown-alg') }
        .to raise_error(JWT::OIDC::UnsupportedAlgorithmError)
    end

    it 'requires the algorithm when the token is given as a payload Hash' do
      expect { verifier_for(:code, nonce: nil).verify!(payload.merge('c_hash' => c_hash)) }
        .to raise_error(ArgumentError, /algorithm/)
    end
  end

  describe 'authorization responses' do
    let(:private_key) { test_pkey('rsa-2048-private.pem') }
    let(:public_key) { test_pkey('rsa-2048-public.pem') }

    # Builds a hybrid flow authorization response where the front-channel
    # ID Token is bound to the authorization code via c_hash.
    def authorization_response(code:, signed_code: code)
      id_token_payload = {
        'iss' => 'https://issuer.example',
        'sub' => 'user-1',
        'aud' => client_id,
        'exp' => Time.now.to_i + 600,
        'iat' => Time.now.to_i,
        'nonce' => nonce,
        'c_hash' => JWT::OIDC::HashAlgorithm.hash_token('RS256', signed_code)
      }

      {
        'id_token' => JWT.encode(id_token_payload, private_key, 'RS256'),
        'code' => code,
        'state' => 'state-1'
      }
    end

    def verify_response(response)
      id_token = JWT::EncodedToken.new(response.fetch('id_token'))
      id_token.verify_signature!(algorithm: 'RS256', key: public_key)
      id_token.verify_claims!(:exp, :iat, aud: client_id, iss: 'https://issuer.example')

      verifier_for(:hybrid, access_token: nil, code: response['code']).verify!(id_token)
    end

    it 'accepts a legitimate response whose c_hash matches the returned code' do
      expect(verify_response(authorization_response(code: code))).to be(true)
    end

    it 'rejects a response whose code was swapped before the exchange' do
      response = authorization_response(code: 'attacker-code', signed_code: code)

      expect { verify_response(response) }.to raise_error(JWT::OIDC::InvalidTokenHashError, /c_hash/)
    end
  end
end
