# frozen_string_literal: true

module JWT
  module SDJWT
    # Separator used by the combined SD-JWT serialization (RFC 9901 section 4).
    SEPARATOR = '~'

    # Default JWT `typ` header value of an SD-JWT.
    SD_JWT_TYPE = 'sd-jwt'

    # JWT `typ` header value of a Key Binding JWT.
    KEY_BINDING_TYPE = 'kb+jwt'

    # Default hash algorithm advertised in the `_sd_alg` claim.
    DEFAULT_HASH_ALGORITHM = 'sha-256'

    # Claim name carrying the digests of hidden object properties.
    SD_KEY = '_sd'

    # Claim name carrying the hash algorithm identifier.
    SD_ALG_KEY = '_sd_alg'

    # Marker that replaces a hidden array element.
    ELLIPSIS = '...'

    # Claim names that may not be used by application claims.
    RESERVED_CLAIM_NAMES = [SD_KEY, SD_ALG_KEY, ELLIPSIS].freeze
  end
end
