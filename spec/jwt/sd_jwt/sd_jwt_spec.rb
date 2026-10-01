# frozen_string_literal: true

require 'spec_helper'

RSpec.describe JWT::SDJWT do
  let(:key) { 'issuer-secret' }
  let(:claims) do
    {
      'name' => 'Alice',
      'address' => { 'country' => 'US', 'locality' => 'Springfield' },
      'nationalities' => %w[US DE]
    }
  end

  let(:issued) do
    JWT::SDJWT.issue(claims, key: key, algorithm: 'HS256') do |issuer|
      issuer.disclose('address', 'country', salt: 'salt-country')
      issuer.disclose('address', 'locality', salt: 'salt-locality')
      issuer.disclose('nationalities', 0, salt: 'salt-us')
      issuer.disclose('nationalities', 1, salt: 'salt-de')
    end
  end

  describe '.issue' do
    it 'returns an IssuedCredential' do
      expect(issued).to be_a(JWT::SDJWT::IssuedCredential)
    end
  end

  describe '.present' do
    it 'selects disclosures by path' do
      presentation = JWT::SDJWT.present(issued, ['address', 'country'], ['nationalities', 0])
      expect(presentation.disclosures.map(&:path)).to eq(
        [['address', 'country'], ['nationalities', 0]]
      )
    end

    it 'selects a claim and its nested descendants with the subtree option' do
      # Mark the geo container too so parent selection pulls nested entries.
      issued_nested = JWT::SDJWT.issue(
        { 'address' => { 'geo' => { 'lat' => 1, 'lon' => 2 } } },
        key: key, algorithm: 'HS256'
      ) do |issuer|
        issuer.disclose('address', 'geo', salt: 'g')
        issuer.disclose('address', 'geo', 'lat', salt: 'la')
        issuer.disclose('address', 'geo', 'lon', salt: 'lo')
      end
      presentation = JWT::SDJWT.present(issued_nested, [['address', 'geo'], :subtree])
      expect(presentation.disclosures.map(&:key)).to eq(%w[geo lat lon])
    end

    it 'passes Disclosure objects through directly' do
      presentation = JWT::SDJWT.present(issued, issued.disclosures.first)
      expect(presentation.disclosures.length).to eq(1)
    end
  end

  describe '.verify' do
    it 'returns only the disclosed claims' do
      presentation = JWT::SDJWT.present(issued, ['address', 'locality'], ['nationalities', 1])
      result = JWT::SDJWT.verify(presentation.to_s, key: key, algorithms: ['HS256'])
      expect(result.claims).to eq(
        'name' => 'Alice',
        'address' => { 'locality' => 'Springfield' },
        'nationalities' => ['DE']
      )
    end

    it 'accepts a Presentation object directly' do
      presentation = JWT::SDJWT.present(issued, ['address', 'country'])
      result = JWT::SDJWT.verify(presentation, key: key, algorithms: ['HS256'])
      expect(result.claims['address']).to eq('country' => 'US')
    end
  end
end
