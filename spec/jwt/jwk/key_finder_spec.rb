# frozen_string_literal: true

RSpec.describe JWT::JWK::KeyFinder do
  describe 'server side key selection' do
    let(:keypair)       { test_pkey('rsa-2048-private.pem') }
    let(:jwk)           { JWT::JWK.new(keypair) }
    let(:other_keypair) { OpenSSL::PKey::RSA.new(2048) }
    let(:algorithm)     { 'RS512' }
    let(:token_payload) { { 'data' => 'something' } }

    def token_for(kid_jwk, headers = {}, alg = algorithm)
      JWT.encode(token_payload, kid_jwk.signing_key, alg, { kid: kid_jwk.kid }.merge(headers))
    end

    def decode(token, jwks, options = {})
      JWT.decode(token, nil, true, { algorithms: [options.delete(:alg) || algorithm], jwks: jwks }.merge(options))
    end

    context 'with rotated keys sharing a kid' do
      let(:old_jwk) { JWT::JWK.new(keypair, alg: 'RS512') }
      let(:new_jwk) { JWT::JWK.new(other_keypair, kid: old_jwk.kid, alg: 'RS256') }

      it 'selects the new key when the token uses its advertised algorithm' do
        token = JWT.encode(token_payload, new_jwk.signing_key, 'RS256', kid: new_jwk.kid)
        jwks = { keys: [old_jwk.export, new_jwk.export] }

        payload, _header = decode(token, jwks, alg: 'RS256')
        expect(payload).to eq(token_payload)
      end

      it 'selects the old key when the token uses its advertised algorithm' do
        token = JWT.encode(token_payload, old_jwk.signing_key, 'RS512', kid: old_jwk.kid)
        jwks = { keys: [new_jwk.export, old_jwk.export] }

        payload, _header = decode(token, jwks, alg: 'RS512')
        expect(payload).to eq(token_payload)
      end

      it 'is independent of the order of the keys in the JWKS' do
        token = JWT.encode(token_payload, new_jwk.signing_key, 'RS256', kid: new_jwk.kid)

        payload_a, = decode(token, { keys: [old_jwk.export, new_jwk.export] }, alg: 'RS256')
        payload_b, = decode(token, { keys: [new_jwk.export, old_jwk.export] }, alg: 'RS256')

        expect(payload_a).to eq(payload_b).and(eq(token_payload))
      end
    end

    context 'with same kid but different key types' do
      let(:hmac_secret) { 'the shared secret'.ljust(64, 'x') }
      let(:hmac_jwk) { JWT::JWK.new(hmac_secret, kid: jwk.kid) }

      it 'does not let an RSA key be used for an HMAC token' do
        token = JWT.encode(token_payload, hmac_secret, 'HS256', kid: jwk.kid)
        jwks = { keys: [jwk.export] }

        expect { JWT.decode(token, nil, true, algorithms: ['HS256'], jwks: jwks) }
          .to raise_error(JWT::SignatureError, /Could not find public key for kid/)
      end

      it 'does not let an HMAC key be used for an RSA token' do
        token = token_for(jwk)
        jwks = { keys: [hmac_jwk.export(include_private: true)] }

        expect { decode(token, jwks) }
          .to raise_error(JWT::SignatureError, /Could not find public key for kid/)
      end

      it 'rejects rather than pick the first key when both fit the token algorithm family' do
        # Both RSA keys survive the policy, so the kid is ambiguous.
        other_rsa = JWT::JWK.new(other_keypair, kid: jwk.kid)
        token = token_for(jwk)
        jwks = { keys: [other_rsa.export, jwk.export] }

        expect { decode(token, jwks) }.to raise_error(JWT::AmbiguousKeyError, /Multiple matching keys found in jwks/)
      end
    end

    describe 'alg metadata' do
      it 'accepts a key whose alg matches the token' do
        signed_jwk = JWT::JWK.new(keypair, alg: algorithm)
        token = JWT.encode(token_payload, signed_jwk.signing_key, algorithm, kid: signed_jwk.kid)

        payload, = decode(token, { keys: [signed_jwk.export] })
        expect(payload).to eq(token_payload)
      end

      it 'ignores missing alg metadata for backwards compatibility' do
        token = token_for(jwk)
        payload, = decode(token, { keys: [jwk.export] })
        expect(payload).to eq(token_payload)
      end

      it 'rejects a key whose alg does not match the token' do
        mismatching_jwk = JWT::JWK.new(keypair, kid: jwk.kid, alg: 'RS256')
        token = token_for(jwk)

        expect { decode(token, { keys: [mismatching_jwk.export] }) }
          .to raise_error(JWT::SignatureError, /Could not find public key for kid/)
      end
    end

    describe 'kty metadata' do
      it 'rejects an oct key advertised for an RSA token' do
        hmac_jwk = JWT::JWK.new('secret'.ljust(64, 'x'), kid: jwk.kid)
        token = token_for(jwk)

        expect { decode(token, { keys: [hmac_jwk.export(include_private: true)] }) }
          .to raise_error(JWT::SignatureError, /Could not find public key for kid/)
      end

      it 'rejects an EC key advertised for an RSA token' do
        ec_jwk = JWT::JWK.new(test_pkey('ec384-private.pem'), kid: jwk.kid)
        token = token_for(jwk)

        expect { decode(token, { keys: [ec_jwk.export] }) }
          .to raise_error(JWT::SignatureError, /Could not find public key for kid/)
      end
    end

    describe 'use metadata' do
      it 'accepts a signature key' do
        signing_jwk = JWT::JWK.new(keypair, use: 'sig')
        token = token_for(signing_jwk)

        payload, = decode(token, { keys: [signing_jwk.export] })
        expect(payload).to eq(token_payload)
      end

      it 'accepts missing use metadata for backwards compatibility' do
        token = token_for(jwk)
        payload, = decode(token, { keys: [jwk.export] })
        expect(payload).to eq(token_payload)
      end

      it 'filters out an encryption key' do
        encryption_jwk = JWT::JWK.new(keypair, use: 'enc')
        token = token_for(jwk)

        expect { decode(token, { keys: [encryption_jwk.export] }) }
          .to raise_error(JWT::SignatureError, /Could not find public key for kid/)
      end
    end

    describe 'key_ops metadata' do
      it 'accepts a key allowed to verify' do
        verifying_jwk = JWT::JWK.new(keypair, key_ops: %w[verify])
        token = token_for(verifying_jwk)

        payload, = decode(token, { keys: [verifying_jwk.export] })
        expect(payload).to eq(token_payload)
      end

      it 'accepts missing key_ops metadata for backwards compatibility' do
        token = token_for(jwk)
        payload, = decode(token, { keys: [jwk.export] })
        expect(payload).to eq(token_payload)
      end

      it 'filters out a sign-only key' do
        sign_only_jwk = JWT::JWK.new(keypair, key_ops: %w[sign])
        token = token_for(jwk)

        expect { decode(token, { keys: [sign_only_jwk.export] }) }
          .to raise_error(JWT::SignatureError, /Could not find public key for kid/)
      end
    end

    describe 'contradictory metadata' do
      it "raises when use is 'enc' but key_ops allows verification" do
        contradictory = JWT::JWK.new(keypair, use: 'enc', key_ops: %w[verify])
        token = token_for(jwk)

        expect { decode(token, { keys: [contradictory.export] }) }
          .to raise_error(JWT::JWKError, /'use' .* and 'key_ops' .* are inconsistent/)
      end

      it "raises when use is 'sig' but key_ops only lists encryption operations" do
        contradictory = JWT::JWK.new(keypair, use: 'sig', key_ops: %w[encrypt decrypt])
        token = token_for(jwk)

        expect { decode(token, { keys: [contradictory.export] }) }
          .to raise_error(JWT::JWKError, /'use' .* and 'key_ops' .* are inconsistent/)
      end

      it 'raises when key_ops is not an array of strings' do
        bad = JWT::JWK.new(keypair, key_ops: 'verify')
        token = token_for(jwk)

        expect { decode(token, { keys: [bad.export] }) }
          .to raise_error(JWT::JWKError, /'key_ops' must be an Array of Strings/)
      end

      it 'raises when alg is incompatible with kty' do
        bad = JWT::JWK.new(keypair, kid: jwk.kid, alg: 'HS256')
        token = token_for(jwk)

        expect { decode(token, { keys: [bad.export] }) }
          .to raise_error(JWT::JWKError, /'alg' .* is incompatible with 'kty'/)
      end
    end

    describe 'thumbprint whitelist' do
      let(:thumbprint) { JWT::JWK::Thumbprint.new(jwk).to_s }

      it 'accepts the key whose thumbprint is whitelisted' do
        other = JWT::JWK.new(other_keypair)
        token = token_for(jwk)
        jwks = { keys: [jwk.export, other.export] }

        payload, = decode(token, jwks, allowed_thumbprints: [thumbprint])
        expect(payload).to eq(token_payload)
      end

      it 'accepts the thumbprint_whitelist alias' do
        token = token_for(jwk)
        payload, = decode(token, { keys: [jwk.export] }, thumbprint_whitelist: [thumbprint])
        expect(payload).to eq(token_payload)
      end

      it 'rejects a key whose thumbprint is not whitelisted' do
        token = token_for(jwk)

        expect { decode(token, { keys: [jwk.export] }, allowed_thumbprints: ['not-a-known-thumbprint']) }
          .to raise_error(JWT::SignatureError, /Could not find public key for kid/)
      end

      it 'rejects every key when the whitelist is empty' do
        token = token_for(jwk)

        expect { decode(token, { keys: [jwk.export] }, allowed_thumbprints: []) }
          .to raise_error(JWT::SignatureError, /Could not find public key for kid/)
      end
    end

    describe 'cardinality' do
      it 'raises no-key error when the jwks is empty' do
        token = token_for(jwk)

        expect { decode(token, { keys: [] }) }
          .to raise_error(JWT::SignatureError, 'No keys found in jwks')
      end

      it 'raises when no key survives the policy' do
        token = token_for(jwk)

        expect { decode(token, { keys: [JWT::JWK.new(other_keypair).export] }) }
          .to raise_error(JWT::SignatureError, /Could not find public key for kid/)
      end

      it 'uses the single surviving key' do
        token = token_for(jwk)
        payload, = decode(token, { keys: [jwk.export] })
        expect(payload).to eq(token_payload)
      end

      it 'raises AmbiguousKeyError when several distinct keys survive' do
        duplicate = JWT::JWK.new(other_keypair, kid: jwk.kid)
        token = token_for(jwk)

        expect { decode(token, { keys: [jwk.export, duplicate.export] }) }
          .to raise_error(JWT::AmbiguousKeyError, /ambiguous/)
      end

      it 'does not treat identical repeated JWK entries as ambiguous' do
        token = token_for(jwk)

        payload, = decode(token, { keys: [jwk.export, jwk.export] })
        expect(payload).to eq(token_payload)
      end
    end

    describe 'jwks loader' do
      it 'still performs the backwards compatible invalidation reload' do
        loader = ->(options) { options[:invalidate] ? { keys: [jwk.export] } : { keys: [] } }
        token = token_for(jwk)

        payload, = decode(token, loader)
        expect(payload).to eq(token_payload)
      end

      it 'does not perform any network fetching of its own' do
        calls = 0
        loader = ->(_options) do
          calls += 1
          { keys: [jwk.export] }
        end
        token = token_for(jwk)

        decode(token, loader)
        expect(calls).to eq(1)
      end
    end
  end

  describe described_class::SelectionPolicy do
    let(:rsa_jwk) { JWT::JWK.new(test_pkey('rsa-2048-private.pem')) }
    let(:other_rsa_jwk) { JWT::JWK.new(OpenSSL::PKey::RSA.new(2048)) }

    def set_with(jwks)
      JWT::JWK::Set.new({ keys: jwks })
    end

    def policy(**overrides)
      defaults = { algorithm: 'RS512', key_field: :kid, kid: rsa_jwk.kid }
      described_class.new(**defaults.merge(overrides))
    end

    it 'picks the unique matching key' do
      expect(policy.pick(set_with([rsa_jwk.export]))).to be_a(JWT::JWK::KeyBase)
    end

    it 'returns nil without a match' do
      expect(policy(kid: 'unknown').pick(set_with([rsa_jwk.export]))).to be_nil
    end

    it 'raises on ambiguity independently of the key order' do
      other = JWT::JWK::RSA.new(other_rsa_jwk.signing_key, kid: rsa_jwk.kid)

      expect { policy.pick(set_with([rsa_jwk.export, other.export])) }.to raise_error(JWT::AmbiguousKeyError)
      expect { policy.pick(set_with([other.export, rsa_jwk.export])) }.to raise_error(JWT::AmbiguousKeyError)
    end
  end
end
