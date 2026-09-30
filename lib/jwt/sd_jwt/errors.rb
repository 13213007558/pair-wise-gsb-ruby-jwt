# frozen_string_literal: true

module JWT
  module SDJwt
    class Error < JWT::Error; end
    class MalformedTokenError < Error; end
    class InvalidDisclosureError < Error; end
    class DuplicateDisclosureError < InvalidDisclosureError; end
    class UnreferencedDisclosureError < InvalidDisclosureError; end
    class ClaimConflictError < InvalidDisclosureError; end
    class ClaimNotFound < Error; end
    class KeyBindingError < Error; end
  end
end
