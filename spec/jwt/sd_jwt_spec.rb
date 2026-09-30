# frozen_string_literal: true

RSpec.describe JWT::SDJwt do
  let(:issuer_private_key) { test_pkey('rsa-2048-private.pem') }
  let(:issuer_public_key) { test_pkey('rsa-2048-public.pem') }
  let(:holder_key) { test_pkey('ec256-private.pem') }
  let(:holder_public_key) { test_pkey('ec256-public.pem') }
  let(:current_time) { 1_700_000_000 }

  let(:payload) do
    {
      'iss' => 'https://issuer.example',
      'given_name' => 'John',
      'family_name' => 'Doe',
      'nullable_note' => nil,
      'address' => { 'country' => 'US', 'locality' => 'Anytown' },
      'degrees' => [{ 'type' => 'Bachelor', 'year' => 2018 }, 'Master']
    }
  end

  let(:disclosable_paths) do
    %w[given_name family_name address.country address.locality degrees.0.type degrees.0.year degrees.1]
  end

  let(:issued) do
    described_class.issue(
      payload: payload,
      signer: { key: issuer_private_key, algorithm: 'RS256' },
      disclosable_paths: disclosable_paths,
      decoy_digests: 2,
      holder_public_key: holder_public_key
    )
  end

  def segments(token)
    token.split('~', -1)
  end

  def issuer_claims(token)
    jwt = segments(token).first
    JWT::JSON.parse(JWT::Base64.url_decode(jwt.split('.')[1]))
  end

  describe '.issue' do
    it 'creates compact serialization with salts, nested digests, array markers and decoys' do
      encoded_disclosures = segments(issued)[1...-1]
      claims = issuer_claims(issued)
      disclosures = encoded_disclosures.map { |segment| described_class::Disclosure.parse(segment) }
      by_digest = disclosures.to_h { |disclosure| [disclosure.digest, disclosure] }
      disclosure_digests = disclosures.map(&:digest)
      decoys = claims['_sd'] - disclosure_digests

      expect(issued).to end_with('~')
      expect(segments(issued).size).to eq(9)
      expect(claims['_sd_alg']).to eq('sha-256')
      expect(claims['cnf']).to eq('jkt' => described_class.key_thumbprint(holder_public_key))
      expect(claims['_sd'].size).to eq(4)
      expect(claims['_sd']).to eq(claims['_sd'].sort)
      expect(decoys.size).to eq(2)
      expect(decoys.map { |digest| JWT::Base64.url_decode(digest).bytesize }).to all(eq(32))
      expect(claims).not_to have_key('given_name')
      expect(claims).not_to have_key('family_name')
      expect(claims['address']).not_to have_key('country')
      expect(claims['address']).not_to have_key('locality')
      expect(claims['degrees'][0]).not_to have_key('type')
      expect(claims['degrees'][1]).to match('...' => a_kind_of(String))
      expect(by_digest.fetch(claims['degrees'][1]['...']).value).to eq('Master')
      expect(claims['nullable_note']).to be_nil
      expect(disclosures.map(&:salt)).to all(a_kind_of(String))
    end

    it 'matches the RFC Appendix A given_name disclosure digest' do
      encoded = 'WyIybENvNmtHeFgwUk1zdExMZnV5THRRIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ'

      expect(described_class.digest(encoded)).to eq('x8jos5pM2QM9kRQRiWNbvgkydGDf91lWFjeAIlUPNVA')
    end

    it 'does not hash a rearranged JSON representation' do
      whitespace = JWT::Base64.url_encode('["salt", "custom", {"b":2, "a":1}]')
      reordered = JWT::Base64.url_encode('["salt","custom",{"a":1,"b":2}]')

      expect(described_class.digest(whitespace)).not_to eq(described_class.digest(reordered))
    end

    it 'verifies a disclosure using the RFC Appendix A salt and encoding' do
      disclosure = described_class::Disclosure.create_property(
        'given_name',
        'John',
        '2lCo6kGxX0RMstLLfuyLtQ'
      )
      claims = {
        'iss' => 'https://issuer.example',
        '_sd' => [disclosure.digest],
        '_sd_alg' => 'sha-256'
      }
      token = "#{JWT.encode(claims, issuer_private_key, 'RS256')}~#{disclosure.encoded}~"
      presentation = described_class.disclose(token, paths: ['given_name'])
      result = described_class.verify(presentation, issuer_key: issuer_public_key, algorithm: 'RS256', current_time: current_time)

      expect(disclosure.encoded).to eq('WyIybENvNmtHeFgwUk1zdExMZnV5THRRIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ')
      expect(result.payload['given_name']).to eq('John')
    end

    it 'always declares the hash algorithm without an empty _sd claim' do
      token = described_class.issue(
        payload: { 'visible' => true },
        signer: { key: issuer_private_key, algorithm: 'RS256' }
      )
      claims = issuer_claims(token)

      expect(claims['_sd_alg']).to eq('sha-256')
      expect(claims).not_to have_key('_sd')
    end
  end

  describe '.disclose and .verify' do
    it 'reveals selected nested fields and array elements while keeping omitted claims absent' do
      presentation = described_class.disclose(
        issued,
        paths: ['given_name', 'address.country', 'degrees.0.type', 'degrees.1']
      )
      result = described_class.verify(
        presentation,
        issuer_key: issuer_public_key,
        algorithm: 'RS256',
        current_time: current_time
      )

      expect(result.payload).to include(
        'given_name' => 'John',
        'address' => { 'country' => 'US' },
        'degrees' => [{ 'type' => 'Bachelor' }, 'Master']
      )
      expect(result.payload).not_to have_key('family_name')
      expect(result.payload['address']).not_to have_key('locality')
      expect(result.payload['degrees'][0]).not_to have_key('year')
      expect(result.payload).not_to have_key('missing_claim')
      expect(result.payload['nullable_note']).to be_nil
      expect(result.header['typ']).to eq('vc+sd-jwt')
      expect(result.key_binding_payload).to be_nil
    end

    it 'reveals all disclosures when paths is :all' do
      presentation = described_class.disclose(issued, paths: :all)
      result = described_class.verify(presentation, issuer_key: issuer_public_key, algorithm: 'RS256', current_time: current_time)

      expect(result.payload).to include(
        'given_name' => 'John',
        'family_name' => 'Doe',
        'address' => { 'country' => 'US', 'locality' => 'Anytown' },
        'degrees' => [{ 'type' => 'Bachelor', 'year' => 2018 }, 'Master']
      )
    end

    it 'includes nested disclosures when the containing disclosure is selected wholly' do
      nested_issued = described_class.issue(
        payload: { 'address' => { 'country' => 'US', 'locality' => 'Anytown' } },
        signer: { key: issuer_private_key, algorithm: 'RS256' },
        disclosable_paths: ['address']
      )
      presentation = described_class.disclose(nested_issued, paths: ['address'])
      result = described_class.verify(presentation, issuer_key: issuer_public_key, algorithm: 'RS256', current_time: current_time)

      expect(result.payload['address']).to eq('country' => 'US', 'locality' => 'Anytown')
    end

    it 'rejects duplicate disclosures' do
      encoded_disclosure = segments(issued)[1]
      duplicated = issued.sub("#{encoded_disclosure}~", "#{encoded_disclosure}~#{encoded_disclosure}~")

      expect do
        described_class.verify(duplicated, issuer_key: issuer_public_key, algorithm: 'RS256', current_time: current_time)
      end.to raise_error(described_class::DuplicateDisclosureError)
    end

    it 'rejects an unreferenced disclosure' do
      extra = described_class::Disclosure.create_property('injected', 'value')
      unreferenced = issued.sub(/~\z/, "~#{extra.encoded}~")

      expect do
        described_class.verify(unreferenced, issuer_key: issuer_public_key, algorithm: 'RS256', current_time: current_time)
      end.to raise_error(described_class::UnreferencedDisclosureError)
    end

    it 'rejects a disclosure that overrides an existing plaintext claim' do
      conflicting = described_class::Disclosure.create_property('iss', 'attacker')
      claims = issuer_claims(issued)
      claims['_sd'] = (claims['_sd'] + [conflicting.digest]).sort
      jwt = JWT.encode(claims, issuer_private_key, 'RS256')
      original_disclosures = segments(issued)[1...-1]
      token = [jwt, *original_disclosures, conflicting.encoded, nil].join('~')

      expect do
        described_class.verify(token, issuer_key: issuer_public_key, algorithm: 'RS256', current_time: current_time)
      end.to raise_error(described_class::ClaimConflictError, /existing plaintext claim/)
    end

    it 'rejects a disclosure value changed after the digest was created' do
      original = described_class::Disclosure.create_property('name', { 'country' => 'US' })
      changed_array = JWT::JSON.parse(JWT::Base64.url_decode(original.encoded))
      changed_array[2] = { 'country' => 'CA' }
      changed = JWT::Base64.url_encode(JWT::JSON.generate(changed_array))

      expect(described_class.digest(changed)).not_to eq(original.digest)
    end

    it 'does not accept a semantically equal disclosure whose encoded JSON was rearranged' do
      original = described_class::Disclosure.create_property('profile', { 'b' => 2, 'a' => 1 }, 'fixed-salt')
      rearranged = JWT::Base64.url_encode(
        JWT::JSON.generate([original.salt, 'profile', { 'a' => 1, 'b' => 2 }])
      )
      claims = {
        '_sd_alg' => 'sha-256',
        '_sd' => [original.digest]
      }
      token = "#{JWT.encode(claims, issuer_private_key, 'RS256')}~#{rearranged}~"

      expect do
        described_class.verify(token, issuer_key: issuer_public_key, algorithm: 'RS256', current_time: current_time)
      end.to raise_error(described_class::UnreferencedDisclosureError)
    end

    it 'treats a literal object key named ... as malformed instead of a marker' do
      claims = {
        '_sd_alg' => 'sha-256',
        'metadata' => { described_class::ARRAY_SD_MARKER => 'not-a-digest' }
      }
      token = "#{JWT.encode(claims, issuer_private_key, 'RS256')}~"

      expect do
        described_class.verify(token, issuer_key: issuer_public_key, algorithm: 'RS256', current_time: current_time)
      end.to raise_error(described_class::MalformedTokenError, /marker/)
    end
  end

  describe 'key binding' do
    let(:presentation) do
      described_class.disclose(
        issued,
        paths: ['given_name'],
        key_binding: {
          holder_key: holder_key,
          audience: 'https://verifier.example',
          nonce: 'nonce-123',
          iat: current_time
        }
      )
    end

    def verify_presentation(**options)
      defaults = {
        issuer_key: issuer_public_key,
        algorithm: 'RS256',
        current_time: current_time + 5,
        audience: 'https://verifier.example',
        nonce: 'nonce-123',
        holder_key: holder_public_key,
        key_binding_leeway: 10
      }
      described_class.verify(presentation, **defaults.merge(options))
    end

    it 'verifies audience, nonce, iat and sd_hash with a caller supplied clock' do
      result = verify_presentation
      prefix = segments(presentation)[0..-2].join('~') + '~'

      expect(result.payload['given_name']).to eq('John')
      expect(result.key_binding_payload).to include(
        'aud' => 'https://verifier.example',
        'nonce' => 'nonce-123',
        'sd_hash' => described_class.sd_hash(prefix)
      )
    end

    it 'rejects a wrong audience' do
      expect { verify_presentation(audience: 'wrong') }.to raise_error(described_class::KeyBindingError, /audience/)
    end

    it 'rejects a wrong nonce' do
      expect { verify_presentation(nonce: 'wrong') }.to raise_error(described_class::KeyBindingError, /nonce/)
    end

    it 'rejects a future iat according to the caller supplied clock' do
      expect { verify_presentation(current_time: current_time - 1, key_binding_leeway: 0) }
        .to raise_error(described_class::KeyBindingError, /future/)
    end

    it 'rejects a key that does not match the issuer cnf' do
      other_key = test_pkey('ec256-public-v2.pem')

      expect { verify_presentation(holder_key: other_key) }.to raise_error(described_class::KeyBindingError, /cnf\.jkt/)
    end

    it 'rejects an altered sd_hash binding string' do
      payload = JWT.decode(presentation.split('~').last, holder_public_key, true, algorithm: 'ES256').first
      payload['sd_hash'] = described_class.digest('tampered')
      kb_jwt = JWT.encode(payload, holder_key, 'ES256', typ: 'kb+jwt')
      tampered = segments(presentation)[0..-2].join('~') + '~' + kb_jwt

      expect { described_class.verify(tampered, issuer_key: issuer_public_key, algorithm: 'RS256', current_time: current_time + 5, audience: 'https://verifier.example', nonce: 'nonce-123', holder_key: holder_public_key, key_binding_leeway: 10) }
        .to raise_error(described_class::KeyBindingError, /sd_hash/)
    end
  end
end
