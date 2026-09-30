# frozen_string_literal: true

module JWT
  module SDJwt
    Result = Struct.new(:payload, :header, :disclosures, :key_binding_payload, keyword_init: true)
  end
end
