# frozen_string_literal: true

require 'spec_helper'

RSpec.describe JWT::SDJWT::Hasher do
  describe '.digest' do
    it 'produces the base64url encoded SHA-256 digest as required by RFC 9901' do
      expected = ::JWT::Base64.url_encode(::OpenSSL::Digest.digest('SHA256', 'hello'))
      expect(described_class.digest('hello')).to eq(expected)
    end

    it 'supports sha-384 and sha-512' do
      expect { described_class.digest('x', 'sha-384') }.not_to raise_error
      expect { described_class.digest('x', 'sha-512') }.not_to raise_error
    end

    it 'rejects unsupported hash algorithms' do
      expect { described_class.digest('x', 'md5') }
        .to raise_error(JWT::SDJWTError, /Unsupported SD-JWT hash algorithm/)
    end
  end

  describe '.random_salt' do
    it 'produces 128 bits of entropy by default' do
      salt = described_class.random_salt
      expect(::JWT::Base64.url_decode(salt).bytesize).to eq(16)
    end

    it 'produces different salts on each call' do
      expect(described_class.random_salt).not_to eq(described_class.random_salt)
    end
  end
end
