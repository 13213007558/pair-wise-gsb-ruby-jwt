# frozen_string_literal: true

RSpec.describe JWT::SDJWT::VerificationResult do
  it 'exposes the verification outputs' do
    disclosure = JWT::SDJWT::Disclosure.new(salt: 's', claim_name: 'k', value: 'v')
    result = described_class.new(
      claims: { 'k' => 'v' },
      header: { 'alg' => 'HS256' },
      disclosures: [disclosure],
      key_binding: { 'nonce' => 'n' }
    )

    expect(result.claims).to eq('k' => 'v')
    expect(result.to_h).to eq('k' => 'v')
    expect(result.header).to eq('alg' => 'HS256')
    expect(result.disclosures).to eq([disclosure])
    expect(result.key_binding).to eq('nonce' => 'n')
  end
end
