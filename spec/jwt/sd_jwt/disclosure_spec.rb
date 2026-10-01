# frozen_string_literal: true

require 'spec_helper'

RSpec.describe JWT::SDJWT::Disclosure do
  describe '.property' do
    it 'creates a three element disclosure for an object member' do
      disclosure = described_class.property('name', 'Alice', 'salt-1')
      expect(disclosure).to be_property
      expect(disclosure).not_to be_array_element
      expect(disclosure.salt).to eq('salt-1')
      expect(disclosure.key).to eq('name')
      expect(disclosure.value).to eq('Alice')
    end

    it 'accepts symbols as claim names' do
      expect(described_class.property(:name, 'Alice', 's').key).to eq('name')
    end

    it 'generates a random salt when none is provided' do
      expect(described_class.property('a', 1).salt).not_to be_empty
    end
  end

  describe '.array_element' do
    it 'creates a two element disclosure for an array element' do
      disclosure = described_class.array_element('US', 'salt-1')
      expect(disclosure).to be_array_element
      expect(disclosure).not_to be_property
      expect(disclosure.salt).to eq('salt-1')
      expect(disclosure.key).to be_nil
      expect(disclosure.value).to eq('US')
    end
  end

  describe '#encoded / .decode' do
    it 'round-trips a property disclosure' do
      disclosure = described_class.property('name', 'Alice', 'salt-1')
      decoded = described_class.decode(disclosure.encoded)
      expect(decoded.key).to eq('name')
      expect(decoded.value).to eq('Alice')
      expect(decoded.salt).to eq('salt-1')
    end

    it 'round-trips an array element disclosure' do
      disclosure = described_class.array_element(42, 'salt-1')
      decoded = described_class.decode(disclosure.encoded)
      expect(decoded.value).to eq(42)
      expect(decoded.key).to be_nil
    end

    it 'rejects malformed disclosure content' do
      aggregate_failures do
        expect { described_class.decode('') }.to raise_error(JWT::SDJWTMalformedError)
        expect { described_class.decode('not-base64-json') }.to raise_error(JWT::SDJWTMalformedError)
        expect { described_class.new(['only-salt']) }.to raise_error(JWT::SDJWTMalformedError)
        expect { described_class.new(['salt', 1, 2, 3]) }.to raise_error(JWT::SDJWTMalformedError)
        expect { described_class.new(['', 'name', 'value']) }.to raise_error(JWT::SDJWTMalformedError)
        expect { described_class.new(['salt', '', 'value']) }.to raise_error(JWT::SDJWTMalformedError)
        expect { described_class.new(['salt', 1]) }.not_to raise_error
        expect { described_class.new(['salt', { 'a' => 1 }]) }.not_to raise_error
      end
    end

    it 'rejects reserved claim names' do
      expect { described_class.property('_sd', 1, 's') }
        .to raise_error(JWT::SDJWTMalformedError, /reserved/)
      expect { described_class.property('...', 1, 's') }
        .to raise_error(JWT::SDJWTMalformedError, /reserved/)
      expect { described_class.property('_sd_alg', 1, 's') }
        .to raise_error(JWT::SDJWTMalformedError, /reserved/)
    end
  end

  describe '#digest' do
    it 'hashes the encoded disclosure' do
      disclosure = described_class.property('name', 'Alice', 'salt-1')
      expect(disclosure.digest).to eq(JWT::SDJWT::Hasher.digest(disclosure.encoded))
    end
  end

  describe 'equality' do
    it 'compares disclosures by their encoded form' do
      a = described_class.property('name', 'Alice', 'salt-1')
      b = described_class.decode(a.encoded)
      expect(a).to eq(b)
      expect([a]).to include(b)
    end
  end
end
