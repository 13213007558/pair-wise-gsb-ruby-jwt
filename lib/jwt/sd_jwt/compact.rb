# frozen_string_literal: true

module JWT
  module SDJWT
    # Parser and serializer for the compact SD-JWT serialization.
    module Compact
      module_function

      def serialize(issued_jwt, disclosures, key_binding_jwt = nil)
        parts = [issued_jwt]
        parts.concat(disclosures)
        serialized = parts.join('~')
        serialized << '~'
        serialized << key_binding_jwt.to_s if key_binding_jwt
        serialized
      end

      def parse(token)
        raise MalformedTokenError, 'SD-JWT must be a String' unless token.is_a?(::String)

        return [token, [], nil] unless token.include?('~')

        if token.end_with?('~')
          key_binding_jwt = nil
          body = token[0..-2]
        else
          key_binding_jwt = token.rpartition('~').last
          body = token.rpartition('~').first
          body = body[0..-2] if body.end_with?('~')
        end

        segments = body.split('~', -1)
        issued_jwt = segments.shift
        disclosures = segments

        validate_jwt!(issued_jwt)
        validate_kb!(key_binding_jwt)
        [issued_jwt, disclosures, key_binding_jwt]
      end

      def presentation_input(issued_jwt, disclosures)
        if disclosures.empty?
          "#{issued_jwt}~"
        else
          ([issued_jwt] + disclosures).join('~') + '~'
        end
      end

      def validate_jwt!(jwt)
        parts = jwt.to_s.split('.', -1)
        raise MalformedTokenError, 'Issuer JWT must contain three parts' unless parts.size == 3
        raise MalformedTokenError, 'Issuer JWT parts must not be empty' if parts.any?(&:empty?)
      end

      def validate_kb!(jwt)
        return if jwt.nil?

        parts = jwt.split('.', -1)
        raise MalformedTokenError, 'Key Binding JWT must contain three parts' unless parts.size == 3
        raise MalformedTokenError, 'Key Binding JWT parts must not be empty' if parts.any?(&:empty?)
      end
    end
  end
end
