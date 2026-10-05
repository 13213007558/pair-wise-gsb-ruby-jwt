# frozen_string_literal: true

RSpec.describe JWT::OIDC::HashAlgorithm do
  describe '.digest_for' do
    {
      'HS256' => 'SHA256', 'RS256' => 'SHA256', 'PS256' => 'SHA256', 'ES256' => 'SHA256', 'ES256K' => 'SHA256',
      'HS384' => 'SHA384', 'RS384' => 'SHA384', 'PS384' => 'SHA384', 'ES384' => 'SHA384',
      'HS512' => 'SHA512', 'RS512' => 'SHA512', 'PS512' => 'SHA512', 'ES512' => 'SHA512'
    }.each do |algorithm, digest|
      it "maps #{algorithm} to #{digest}" do
        expect(described_class.digest_for(algorithm).name).to eq(digest)
      end
    end

    it 'accepts algorithm names case insensitively' do
      expect(described_class.digest_for('rs256').name).to eq('SHA256')
    end

    it 'rejects the none algorithm instead of falling back to SHA-256' do
      expect { described_class.digest_for('none') }.to raise_error(JWT::OIDC::UnsupportedAlgorithmError)
    end

    it 'rejects unknown algorithms instead of falling back to SHA-256' do
      expect { described_class.digest_for('HS999') }.to raise_error(JWT::OIDC::UnsupportedAlgorithmError)
      expect { described_class.digest_for(nil) }.to raise_error(JWT::OIDC::UnsupportedAlgorithmError)
    end
  end

  describe '.hash_token' do
    it 'matches the at_hash example from OpenID Connect Core 1.0' do
      # https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
      expect(described_class.hash_token('RS256', 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y'))
        .to eq('77QmUPtjPfzWtF2AnpK9RQ')
    end

    it 'uses the left-most half of the digest of the signature algorithm' do
      digest = OpenSSL::Digest.new('SHA384').digest('token-value')
      expect(described_class.hash_token('ES384', 'token-value'))
        .to eq(JWT::Base64.url_encode(digest[0, 24]))
    end
  end
end
