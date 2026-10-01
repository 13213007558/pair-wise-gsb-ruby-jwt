# frozen_string_literal: true

require 'spec_helper'

RSpec.describe JWT::SDJWT::Presentation do
  let(:jwt) { 'eyJhbGciOiJIUzI1NiJ9.e30.sig' }
  let(:disclosure) { JWT::SDJWT::Disclosure.property('a', 1, 'salt-1') }

  describe '#to_s' do
    it 'serializes without a trailing separator' do
      presentation = described_class.new(jwt, [disclosure])
      expect(presentation.to_s).to eq("#{jwt}~#{disclosure.encoded}")
    end

    it 'serializes an empty presentation as the bare JWT' do
      expect(described_class.new(jwt).to_s).to eq(jwt)
    end

    it 'appends the Key Binding JWT when present' do
      presentation = described_class.new(jwt, [disclosure], 'kbjwt.a.b')
      expect(presentation.to_s).to eq("#{jwt}~#{disclosure.encoded}~kbjwt.a.b")
    end
  end

  describe '.parse' do
    it 'parses a presentation without a Key Binding JWT' do
      presentation = described_class.parse("#{jwt}~#{disclosure.encoded}")
      expect(presentation.jwt).to eq(jwt)
      expect(presentation.disclosures.length).to eq(1)
      expect(presentation.key_binding_jwt).to be_nil
    end

    it 'parses the issuer-SD-JWT form with a trailing separator' do
      presentation = described_class.parse("#{jwt}~#{disclosure.encoded}~")
      expect(presentation.disclosures.length).to eq(1)
      expect(presentation.key_binding_jwt).to be_nil
    end

    it 'parses a presentation with a Key Binding JWT' do
      presentation = described_class.parse("#{jwt}~#{disclosure.encoded}~a.b.c")
      expect(presentation.key_binding_jwt).to eq('a.b.c')
    end

    it 'parses a bare JWT without separators' do
      presentation = described_class.parse(jwt)
      expect(presentation.disclosures).to be_empty
      expect(presentation.key_binding_jwt).to be_nil
    end

    it 'rejects malformed serializations' do
      expect { described_class.parse(nil) }.to raise_error(JWT::SDJWTMalformedError)
      expect { described_class.parse('~x') }.to raise_error(JWT::SDJWTMalformedError)
      expect { described_class.parse('garbage') }.to raise_error(JWT::SDJWTMalformedError)
      expect { described_class.parse("#{jwt}~~#{disclosure.encoded}") }
        .to raise_error(JWT::SDJWTMalformedError)
    end
  end

  describe '#add' do
    it 'accepts Disclosure objects and encoded strings' do
      presentation = described_class.new(jwt)
      presentation.add(disclosure)
      presentation.add(disclosure.encoded)
      expect(presentation.disclosures.length).to eq(1)
    end

    it 'does not add the same disclosure twice' do
      presentation = described_class.new(jwt)
      presentation << disclosure << disclosure
      expect(presentation.disclosures.length).to eq(1)
    end
  end
end
