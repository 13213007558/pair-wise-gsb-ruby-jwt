# frozen_string_literal: true

RSpec.describe JWT::Claims::MaxLifetime do
  subject(:verify!) { described_class.new(max_lifetime: max_lifetime).verify!(context: SpecSupport::Token.new(payload: payload)) }

  let(:now) { 1_000_000 }
  let(:max_lifetime) { 300 }

  context 'with a valid lifetime' do
    let(:payload) { { 'iat' => now, 'exp' => now + 200 } }

    it 'passes validation' do
      verify!
    end
  end

  context 'with a lifetime exactly at the maximum' do
    let(:payload) { { 'iat' => now, 'exp' => now + 300 } }

    it 'passes validation' do
      verify!
    end
  end

  context 'with a lifetime exceeding the maximum' do
    let(:payload) { { 'iat' => now, 'exp' => now + 301 } }

    it 'raises JWT::MaxLifetimeExceeded' do
      expect { verify! }.to raise_error(JWT::MaxLifetimeExceeded, /301 seconds.*300 seconds/)
    end
  end

  context 'when iat is missing' do
    let(:payload) { { 'exp' => now + 100 } }

    it 'raises JWT::MissingRequiredClaim' do
      expect { verify! }.to raise_error(JWT::MissingRequiredClaim, 'Missing required claim iat')
    end
  end

  context 'when exp is missing' do
    let(:payload) { { 'iat' => now } }

    it 'raises JWT::MissingRequiredClaim' do
      expect { verify! }.to raise_error(JWT::MissingRequiredClaim, 'Missing required claim exp')
    end
  end

  context 'when a claim is not numeric' do
    let(:payload) { { 'iat' => 'soon', 'exp' => now } }

    it 'raises JWT::InvalidPayload' do
      expect { verify! }.to raise_error(JWT::InvalidPayload, /iat claim must be a Numeric/)
    end
  end

  context 'when exp precedes iat' do
    let(:payload) { { 'iat' => now, 'exp' => now - 10 } }

    it 'raises JWT::InvalidPayload' do
      expect { verify! }.to raise_error(JWT::InvalidPayload, 'The exp claim must not precede the iat claim')
    end
  end

  describe '#initialize' do
    it 'rejects a non-numeric lifetime' do
      expect { described_class.new(max_lifetime: '300') }.to raise_error(ArgumentError, /Numeric/)
    end

    it 'rejects a non-positive lifetime' do
      expect { described_class.new(max_lifetime: 0) }.to raise_error(ArgumentError, /greater than zero/)
    end
  end
end
