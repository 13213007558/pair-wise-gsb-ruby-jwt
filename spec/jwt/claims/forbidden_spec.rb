# frozen_string_literal: true

RSpec.describe JWT::Claims::Forbidden do
  let(:payload) { { 'sub' => 'user' } }

  subject(:verify!) { described_class.new(forbidden_claims: forbidden_claims).verify!(context: SpecSupport::Token.new(payload: payload)) }

  context 'when none of the forbidden claims are present' do
    let(:forbidden_claims) { %w[reset_purpose scope] }

    it 'passes validation' do
      verify!
    end
  end

  context 'when the list of forbidden claims is empty' do
    let(:forbidden_claims) { [] }

    it 'passes validation' do
      verify!
    end
  end

  context 'when a forbidden claim is present' do
    let(:payload) { { 'reset_purpose' => 'password' } }
    let(:forbidden_claims) { %w[reset_purpose scope] }

    it 'raises JWT::ForbiddenClaimError naming the claim' do
      expect { verify! }.to raise_error(JWT::ForbiddenClaimError, 'Forbidden claim(s) present: reset_purpose')
    end
  end

  context 'when several forbidden claims are present' do
    let(:payload) { { 'reset_purpose' => 'password', 'scope' => 'admin' } }
    let(:forbidden_claims) { %w[reset_purpose scope] }

    it 'names all of them' do
      expect { verify! }.to raise_error(JWT::ForbiddenClaimError, 'Forbidden claim(s) present: reset_purpose, scope')
    end
  end
end
