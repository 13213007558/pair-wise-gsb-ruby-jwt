# frozen_string_literal: true

module JWT
  module SDJWT
    # Base error for Selective Disclosure JWT processing.
    class Error < JWT::Error; end

    # Raised when an SD-JWT disclosure is malformed.
    class MalformedDisclosureError < Error; end

    # Raised when an SD-JWT or Key Binding JWT is structurally invalid.
    class MalformedTokenError < Error; end

    # Raised when the set of disclosures is invalid for the signed payload.
    class DisclosureVerificationError < Error; end

    # Raised when Key Binding verification fails.
    class KeyBindingError < Error; end
  end
end
