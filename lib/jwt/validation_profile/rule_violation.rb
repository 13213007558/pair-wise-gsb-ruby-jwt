# frozen_string_literal: true

module JWT
  class ValidationProfile
    # Represents a single rule that a token violated when checked against a profile.
    #
    # The object intentionally carries only the name of the violated rule and a
    # human readable message. Verification keys and other signing material are
    # never part of it, so violations can be surfaced to clients safely.
    RuleViolation = Struct.new(:rule, :message, keyword_init: true) do
      # @return [String] a compact representation of the violation.
      def to_s
        "#{rule}: #{message}"
      end
    end
  end
end
