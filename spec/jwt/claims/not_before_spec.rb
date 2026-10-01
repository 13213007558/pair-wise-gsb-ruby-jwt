# frozen_string_literal: true

RSpec.describe JWT::Claims::NotBefore do
  let(:payload) { { 'nbf' => (Time.now.to_i + 5) } }

  describe '#verify!' do
    context 'when nbf is in the future' do
      it 'raises JWT::ImmatureSignature' do
        expect { described_class.new(leeway: 0).verify!(context: SpecSupport::Token.new(payload: payload)) }.to raise_error(JWT::ImmatureSignature)
      end
    end

    context 'when nbf is in the past' do
      let(:payload) { { 'nbf' => (Time.now.to_i - 5) } }

      it 'does not raise error' do
        expect { described_class.new(leeway: 0).verify!(context: SpecSupport::Token.new(payload: payload)) }.not_to raise_error
      end
    end

    context 'when leeway is given' do
      it 'does not raise error' do
        expect { described_class.new(leeway: 10).verify!(context: SpecSupport::Token.new(payload: payload)) }.not_to raise_error
      end
    end
  end
end

RSpec.describe JWT::Claims::NotBefore, 'clock injection' do
  it 'uses the injected clock when evaluating the nbf claim' do
    context = SpecSupport::Token.new(payload: { 'nbf' => 100 })
    verifier = described_class.new(leeway: 0, clock: -> { Time.at(99) })
    expect { verifier.verify!(context: context) }.to raise_error(JWT::ImmatureSignature)

    described_class.new(leeway: 0, clock: -> { Time.at(100) }).verify!(context: context)
  end
end
