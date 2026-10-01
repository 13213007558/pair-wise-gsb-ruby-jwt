# frozen_string_literal: true

require 'spec_helper'

RSpec.describe JWT::SDJWT::Issuer do
  let(:key) { 'issuer-secret' }
  let(:claims) do
    {
      name: 'Alice',
      age: 42,
      address: { country: 'US', locality: 'Springfield' },
      nationalities: %w[US DE]
    }
  end

  def payload_of(issued)
    header, payload, = issued.jwt.split('.')
    ::JWT::JSON.parse(::JWT::Base64.url_decode(payload))
  end

  describe '#initialize' do
    it 'requires a JSON object payload' do
      expect { described_class.new(['nope']) }.to raise_error(JWT::SDJWTIssueError, /JSON object/)
    end

    it 'rejects reserved claim names anywhere in the payload' do
      expect { described_class.new({ '_sd' => [] }) }.to raise_error(JWT::SDJWTIssueError, /reserved/)
      expect { described_class.new({ 'a' => { '...' => 1 } }) }.to raise_error(JWT::SDJWTIssueError, /reserved/)
      expect { described_class.new({ 'a' => [{ '_sd_alg' => 'sha-256' }] }) }
        .to raise_error(JWT::SDJWTIssueError, /reserved/)
    end

    it 'rejects unsupported hash algorithms' do
      expect { described_class.new({ a: 1 }, hash_algorithm: 'md5') }
        .to raise_error(JWT::SDJWTError)
    end
  end

  describe '#disclose' do
    it 'marks an object member as disclosable' do
      issuer = described_class.new(claims)
      issuer.disclose(:name, salt: 's')
      issued = issuer.issue!(key: key, algorithm: 'HS256')
      payload = payload_of(issued)
      expect(payload).not_to have_key('name')
      expect(payload['_sd'].length).to eq(1)
      expect(issued.disclosures.first.key).to eq('name')
    end

    it 'supports nested object members' do
      issuer = described_class.new(claims)
      issuer.disclose('address', 'country', salt: 's')
      issued = issuer.issue!(key: key, algorithm: 'HS256')
      payload = payload_of(issued)
      expect(payload['address']).not_to have_key('country')
      expect(payload['address']['_sd'].length).to eq(1)
    end

    it 'supports array elements' do
      issuer = described_class.new(claims)
      issuer.disclose('nationalities', 0, salt: 's')
      issued = issuer.issue!(key: key, algorithm: 'HS256')
      payload = payload_of(issued)
      expect(payload['nationalities'].first).to include('...' => kind_of(String))
      expect(payload['nationalities'].last).to eq('DE')
    end

    it 'supports all elements of an array' do
      issuer = described_class.new(claims)
      issuer.disclose('nationalities', 0, salt: 's1')
      issuer.disclose('nationalities', 1, salt: 's2')
      issued = issuer.issue!(key: key, algorithm: 'HS256')
      payload = payload_of(issued)
      expect(payload['nationalities'].length).to eq(2)
      expect(payload['nationalities']).to all(include('...'))
      expect(issued.disclosures.map(&:value)).to eq(%w[US DE])
    end

    it 'supports recursive disclosure of nested objects' do
      issuer = described_class.new(claims)
      issuer.disclose('address', salt: 's-a')
      issuer.disclose('address', 'locality', salt: 's-l')
      issued = issuer.issue!(key: key, algorithm: 'HS256')
      payload = payload_of(issued)
      expect(payload).not_to have_key('address')
      address = issued.disclosures.find { |d| d.key == 'address' }.value
      expect(address['country']).to eq('US')
      expect(address).not_to have_key('locality')
      expect(address['_sd'].length).to eq(1)
    end

    it 'rejects unknown paths' do
      issuer = described_class.new(claims)
      expect { issuer.disclose(:unknown) }.to raise_error(JWT::SDJWTIssueError)
      expect { issuer.disclose('address', 'unknown') }.to raise_error(JWT::SDJWTIssueError)
      expect { issuer.disclose('nationalities', 5) }.to raise_error(JWT::SDJWTIssueError)
      expect { issuer.disclose('name', 0) }.to raise_error(JWT::SDJWTIssueError)
    end

    it 'rejects invalid path segments' do
      issuer = described_class.new(claims)
      expect { issuer.disclose }.to raise_error(JWT::SDJWTIssueError)
      expect { issuer.disclose(nil) }.to raise_error(JWT::SDJWTIssueError)
      expect { issuer.disclose(:a) }.to raise_error(JWT::SDJWTIssueError)
      expect { issuer.disclose('nationalities', -1) }.to raise_error(JWT::SDJWTIssueError)
    end

    it 'rejects reserved names and duplicate paths' do
      issuer = described_class.new(claims)
      expect { issuer.disclose(:_sd) }.to raise_error(JWT::SDJWTIssueError)
      issuer.disclose(:name)
      expect { issuer.disclose(:name) }.to raise_error(JWT::SDJWTIssueError, /already marked/)
    end
  end

  describe '#issue!' do
    it 'sets the _sd_alg claim and the sd-jwt typ header' do
      issued = described_class.new(claims).issue!(key: key, algorithm: 'HS256')
      header = ::JWT::JSON.parse(::JWT::Base64.url_decode(issued.jwt.split('.').first))
      expect(payload_of(issued)['_sd_alg']).to eq('sha-256')
      expect(header['typ']).to eq('sd-jwt')
      expect(header['alg']).to eq('HS256')
    end

    it 'honours a different hash algorithm' do
      issued = described_class.new(claims, hash_algorithm: 'sha-384')
                   .tap { |i| i.disclose(:name, salt: 's') }
                   .issue!(key: key, algorithm: 'HS256')
      expect(payload_of(issued)['_sd_alg']).to eq('sha-384')
    end

    it 'merges additional header fields without overriding alg' do
      issued = described_class.new(claims).issue!(key: key, algorithm: 'HS256',
                                                  header_fields: { kid: 'key-1', typ: 'custom' })
      header = ::JWT::JSON.parse(::JWT::Base64.url_decode(issued.jwt.split('.').first))
      expect(header['kid']).to eq('key-1')
      expect(header['typ']).to eq('custom')
    end

    it 'produces a signed JWT verifiable with the existing JWT.decode interface' do
      issued = described_class.new(claims).issue!(key: key, algorithm: 'HS256')
      payload, = JWT.decode(issued.jwt, key, true, algorithms: ['HS256'])
      expect(payload['_sd_alg']).to eq('sha-256')
    end

    it 'reuses JWK keys for signing' do
      jwk = JWT::JWK.create_from(OpenSSL::PKey::EC.generate('prime256v1'))
      issued = described_class.new(claims).issue!(key: jwk, algorithm: 'ES256')
      expect { JWT.decode(issued.jwt, jwk.verify_key, true, algorithms: ['ES256']) }.not_to raise_error
    end

    it 'can only be issued once' do
      issuer = described_class.new(claims)
      issuer.issue!(key: key, algorithm: 'HS256')
      expect { issuer.issue!(key: key, algorithm: 'HS256') }.to raise_error(JWT::SDJWTIssueError, /already issued/)
    end
  end

  describe JWT::SDJWT::IssuedCredential do
    it 'serializes to the combined issuer SD-JWT format ending in ~' do
      issued = JWT::SDJWT::Issuer.new(claims).tap { |i| i.disclose(:name, salt: 's') }
                                        .issue!(key: key, algorithm: 'HS256')
      expect(issued.to_s).to end_with('~')
      expect(issued.to_s.count('~')).to eq(issued.disclosures.length + 1)
    end
  end
end
