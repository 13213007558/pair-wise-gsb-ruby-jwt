# frozen_string_literal: true

module JWT
  module SDJwt
    class Compact
      Parsed = Struct.new(:jwt, :disclosures, :key_binding_jwt, :key_binding_input, keyword_init: true)

      def self.parse(token)
        raise MalformedTokenError, 'SD-JWT must be a string' unless token.is_a?(String)
        raise MalformedTokenError, 'SD-JWT is malformed' unless token.include?('~')

        if token.end_with?('~')
          body = token[0..-2]
          raise MalformedTokenError, 'SD-JWT is malformed' if body.end_with?('~')

          segments = body.split('~')
          key_binding_input = body + '~'
          key_binding_jwt = nil
        else
          segments = token.split('~')
          key_binding_jwt = segments.pop
          key_binding_input = segments.join('~') + '~'
        end

        jwt = segments.shift
        raise MalformedTokenError, 'SD-JWT is malformed' if jwt.nil? || jwt.empty? || segments.any?(&:empty?)

        Parsed.new(
          jwt: jwt,
          disclosures: parse_disclosures(segments),
          key_binding_jwt: key_binding_jwt,
          key_binding_input: key_binding_input
        )
      end

      def self.parse_disclosures(segments)
        encoded_disclosures = {}
        segments.map do |segment|
          if encoded_disclosures.key?(segment)
            raise DuplicateDisclosureError, 'Duplicate disclosure was presented'
          end

          encoded_disclosures[segment] = true
          Disclosure.parse(segment)
        end
      end
    end
  end
end
