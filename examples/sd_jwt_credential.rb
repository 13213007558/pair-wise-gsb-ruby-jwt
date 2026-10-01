#!/usr/bin/env ruby
# frozen_string_literal: true

# Demonstration of RFC 9901 SD-JWT selective disclosure with ruby-jwt.
#
# The credential contains a name, an age, an address (nested object) and a
# list of nationalities (array). Every claim is made selectively disclosable,
# and the same issuer signed credential is presented twice with two different
# disclosure sets. A third presentation smuggles in an unrelated disclosure
# and is rejected by the verifier. Finally a presentation with a Key Binding
# JWT is shown.
#
# Everything runs offline: the issuer and holder keys are generated locally
# and the salts are fixed, so the output of this script is deterministic.

$LOAD_PATH.unshift(File.join(__dir__, '..', 'lib'))
require 'jwt'

# --- Local keys -----------------------------------------------------------

issuer_key = OpenSSL::PKey::EC.generate('prime256v1')
issuer_public_key = issuer_key.public_key
holder_key = OpenSSL::PKey::EC.generate('prime256v1')
holder_jwk = JWT::JWK.create_from(holder_key).export.reject { |k, _| k == :kid }

# --- Fixed salts, handed out in issuance order ----------------------------

FIXED_SALTS = %w[
  salt-01 salt-02 salt-03 salt-04 salt-05 salt-06 salt-07
].freeze
salt_counter = -1
fixed_salts = -> { FIXED_SALTS[salt_counter += 1] }

# --- The credential -------------------------------------------------------

credential = {
  'iss' => 'https://issuer.example',
  'name' => 'Alice Chen',
  'age' => 29,
  'address' => {
    'street' => '12 Maple Street',
    'locality' => 'Berlin',
    'country' => 'DE'
  },
  'nationalities' => %w[CN DE]
}

disclosable_paths = [
  'name',
  'age',
  'address.street',
  'address.locality',
  'address.country',
  'nationalities[0]',
  'nationalities[1]'
]

sd_jwt = JWT::SDJWT.issue(
  claims: credential,
  disclosable: disclosable_paths,
  key: issuer_key,
  algorithm: 'ES256',
  holder_jwk: holder_jwk,
  salt_provider: fixed_salts
)

issuer_payload = sd_jwt.unverified_payload
puts '== Issuer signed JWT payload (all selective claims are hidden behind digests) =='
puts JSON.pretty_generate(issuer_payload.reject { |k, _| %w[iss _sd_alg cnf].include?(k) })
puts

def verify!(presentation, label, issuer_public_key, **kb_options)
  result = JWT::SDJWT.verify(
    presentation,
    key: issuer_public_key,
    algorithm: 'ES256',
    claims: false,
    **kb_options
  )
  puts "== #{label}: verification succeeded =="
  puts JSON.pretty_generate(result.claims.reject { |k, _| k == 'cnf' })
  puts
  result
rescue JWT::Error => e
  puts "== #{label}: verification failed =="
  puts "   #{e.class}: #{e.message}"
  puts
  nil
end

# --- Presentation 1: only name and age ------------------------------------

presentation_1 = JWT::SDJWT.present(sd_jwt, %w[name age])
verify!(presentation_1, 'Presentation 1 (name + age)', issuer_public_key)

# --- Presentation 2: nested address members + one array element -----------

presentation_2 = JWT::SDJWT.present(
  sd_jwt,
  %w[address.street address.locality address.country nationalities[1]]
)
verify!(presentation_2, 'Presentation 2 (address + one nationality)', issuer_public_key)

# --- Presentation 3: an unrelated disclosure is smuggled in ---------------

# Build an extra disclosure for a claim that is not part of this credential.
stranger = JWT::SDJWT::Disclosure.new(salt: 'salt-stranger', claim_name: 'is_admin', value: true)
tampered = JWT::SDJWT::CompoundSdJwt.new(
  issuer_jwt: presentation_1.issuer_jwt,
  disclosures: presentation_1.disclosures + [stranger]
)
verify!(tampered, 'Presentation 3 (name + age with an unrelated disclosure)', issuer_public_key)

# --- Presentation 4: Key Binding JWT --------------------------------------

presentation_4 = JWT::SDJWT.present(sd_jwt, %w[name])
presentation_4 = JWT::SDJWT.bind(
  presentation_4,
  audience: 'https://verifier.example',
  nonce: 'verifier-nonce-98765',
  key: holder_key
)
result = verify!(
  presentation_4,
  'Presentation 4 (name + Key Binding JWT)',
  issuer_public_key,
  audience: 'https://verifier.example',
  nonce: 'verifier-nonce-98765'
)
puts "Key Binding JWT claims: #{result.key_binding.inspect}" if result
