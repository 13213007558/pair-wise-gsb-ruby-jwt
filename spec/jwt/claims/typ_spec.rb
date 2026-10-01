# frozen_string_literal: true

RSpec.describe JWT::Claims::Typ do
  let(:header) { { 'typ' => 'access' } }

  subject(:verify!) { described_class.new(expected_typ: expected_typ).verify!(context: SpecSupport::Token.new(payload: {}, header: header)) }

  context 'when the header typ matches a single expected value' do
    let(:expected_typ) { 'access' }

    it 'passes validation' do
      verify!
    end
  end

  context 'when the header typ matches one of several expected values' do
    let(:expected_typ) { %w[access refresh] }

    it 'passes validation' do
      verify!
    end
  end

  context 'when the header typ differs' do
    let(:header) { { 'typ' => 'password_reset' } }
    let(:expected_typ) { 'access' }

    it 'raises JWT::InvalidTypError' do
      expect { verify! }.to raise_error(JWT::InvalidTypError, 'Invalid typ. Expected access, received password_reset')
    end
  end

  context 'when the header has no typ' do
    let(:header) { {} }
    let(:expected_typ) { 'access' }

    it 'raises JWT::InvalidTypError mentioning the missing value' do
      expect { verify! }.to raise_error(JWT::InvalidTypError, 'Invalid typ. Expected access, received <none>')
    end
  end

  context 'when the context carries no header at all' do
    let(:expected_typ) { 'access' }

    it 'raises JWT::InvalidTypError' do
      expect { described_class.new(expected_typ: expected_typ).verify!(context: SpecSupport::Token.new(payload: {})) }
        .to raise_error(JWT::InvalidTypError, /<none>/)
    end
  end
end
