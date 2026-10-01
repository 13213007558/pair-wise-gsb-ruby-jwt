#!/usr/bin/env ruby
# frozen_string_literal: true

# RFC 9901 Selective Disclosure for JWTs (SD-JWT) demonstration.
#
# Runs completely offline: the issuer and holder keys are generated locally
# and every disclosure uses a fixed salt, so the output is reproducible.
#
# Run with:
#   ruby -Ilib examples/sd_jwt_demo.rb

require 'jwt'
require 'pp'

puts "== RFC 9901 SD-JWT demonstration =="
puts

# ---------------------------------------------------------------------------
# 1. Keys generated locally (no credential network protocol is involved)
# ---------------------------------------------------------------------------
issuer_key = OpenSSL::PKey::EC.generate('prime256v1')
issuer_jwk = JWT::JWK.create_from(issuer_key)

holder_key = OpenSSL::PKey::EC.generate('prime256v1')
holder_jwk = JWT::JWK.create_from(holder_key).export

# ---------------------------------------------------------------------------
# 2. The credential: name (object member), age, a nested address and an array.
#    Every salt is fixed for the demo.
# ---------------------------------------------------------------------------
credential_claims = {
  'iss' => 'https://issuer.example',
  'vct' => 'https://issuer.example/credentials/id-card',
  'cnf' => { 'jwk' => holder_jwk },
  'name' => 'Alice Smith',
  'age' => 42,
  'address' => {
    'country' => 'US',
    'locality' => 'Springfield'
  },
  'nationalities' => ['US', 'DE']
}

issued = JWT::SDJWT.issue(
  credential_claims,
  key: issuer_key,
  algorithm: 'ES256'
) do |issuer|
  issuer.disclose('name', salt: 'demo-salt-name')
  issuer.disclose('age', salt: 'demo-salt-age')
  issuer.disclose('address', 'country', salt: 'demo-salt-country')
  issuer.disclose('address', 'locality', salt: 'demo-salt-locality')
  issuer.disclose('nationalities', 0, salt: 'demo-salt-us')
  issuer.disclose('nationalities', 1, salt: 'demo-salt-de')
end

puts "Issuer JWT (payload):"
payload = JWT::JSON.parse(JWT::Base64.url_decode(issued.jwt.split('.')[1]))
pp payload
puts
puts "Disclosures created by the issuer (#{issued.disclosures.length}):"
issued.disclosures.each { |d| puts "  #{d.path.inspect} -> #{d.encoded[0, 24]}..." }
puts

# ---------------------------------------------------------------------------
# 3. Two different disclosure sets for the SAME credential.
# ---------------------------------------------------------------------------
# Presentation A: identity + country + first nationality
presentation_a = JWT::SDJWT.present(
  issued,
  'name',
  ['address', 'country'],
  ['nationalities', 0]
)

# Presentation B: age + full address + nationalities, plus a Key Binding JWT
presentation_b = JWT::SDJWT.present(
  issued,
  'age',
  ['address', 'country'], ['address', 'locality'],
  ['nationalities', 0], ['nationalities', 1]
)
JWT::SDJWT.bind_key(
  presentation_b,
  key: holder_key,
  algorithm: 'ES256',
  audience: 'https://verifier.example',
  nonce: 'demo-verifier-nonce'
)

[
  ['A (name, country, first nationality)', presentation_a, nil],
  ['B (age, full address, nationalities, Key Binding)', presentation_b, 'demo-verifier-nonce']
].each do |label, presentation, nonce|
  puts "-- Verifying presentation #{label}"
  result = JWT::SDJWT.verify(
    presentation.to_s,
    key: issuer_jwk.verify_key,
    algorithms: ['ES256'],
    expected_audience: nonce && 'https://verifier.example',
    expected_nonce: nonce
  )
  puts "   Disclosed claims:"
  pp result.claims
  puts "   Key Binding JWT: #{result.key_binding ? 'verified (aud, nonce, sd_hash)' : 'not present'}"
  puts
end

# ---------------------------------------------------------------------------
# 4. Tampering: one of the presentations carries an unrelated disclosure.
# ---------------------------------------------------------------------------
unrelated = JWT::SDJWT::Disclosure.property('is_minor', true, 'demo-salt-unrelated')
tampered = "#{presentation_a.to_s}~#{unrelated.encoded}"

puts "-- Verifying a presentation with an unrelated disclosure"
begin
  JWT::SDJWT.verify(tampered, key: issuer_jwk.verify_key, algorithms: ['ES256'])
  puts '   UNEXPECTED: the presentation was accepted!'
rescue JWT::SDJWTUnreferencedDisclosureError => e
  puts "   Rejected as required: #{e.message}"
end
puts

# ---------------------------------------------------------------------------
# 5. Other attack surfaces
# ---------------------------------------------------------------------------
def expect_rejection(label)
  yield
  puts "   UNEXPECTED: #{label} was accepted"
rescue JWT::SDJWTVerificationError, JWT::VerificationError => e
  puts "   #{label}: #{e.class.name.split('::').last} - #{e.message}"
end

puts "-- Additional rejection checks"
expect_rejection('Forged issuer signature') do
  JWT::SDJWT.verify(presentation_a.to_s, key: OpenSSL::PKey::EC.generate('prime256v1'), algorithms: ['ES256'])
end

# Same disclosure twice
dup = "#{presentation_a.jwt}~#{presentation_a.disclosures.map(&:encoded).join('~')}~#{presentation_a.disclosures.first.encoded}"
expect_rejection('Duplicate disclosure') do
  JWT::SDJWT.verify(dup, key: issuer_jwk.verify_key, algorithms: ['ES256'])
end

# Wrong Key Binding nonce
expect_rejection('Key Binding with a wrong nonce') do
  JWT::SDJWT.verify(presentation_b.to_s, key: issuer_jwk.verify_key, algorithms: ['ES256'],
                    expected_audience: 'https://verifier.example', expected_nonce: 'wrong-nonce')
end
