# frozen_string_literal: true

module JWT
  module JWS
    # Represents a single signature in a JWS JSON Serialization as defined in
    # RFC 7515 sections 7.2.1 and 7.2.2.
    class Signature
      # Initializes a new Signature from the raw JSON member values.
      #
      # @param protected_header [String, nil] the Base64url encoded protected header.
      # @param header [Hash, nil] the unprotected header parameters.
      # @param signature [String, nil] the Base64url encoded signature.
      def initialize(protected_header: nil, header: nil, signature: nil)
        @encoded_protected_header = protected_header
        @unprotected_header       = header
        @encoded_signature        = signature
      end

      # @return [String, nil] the Base64url encoded protected header.
      attr_reader :encoded_protected_header

      # @return [Hash, nil] the unprotected header parameters.
      attr_reader :unprotected_header

      # @return [String, nil] the Base64url encoded signature.
      attr_reader :encoded_signature

      # @return [String] the decoded signature bytes.
      def signature
        @signature ||= ::JWT::Base64.url_decode(encoded_signature || '')
      end

      # @return [Hash, nil] the decoded protected header parameters.
      def protected_header
        @protected_header ||= parse_protected_header
      end

      # @return [Hash] the merged protected and unprotected header parameters.
      # @raise [JWT::MalformedTokenError] if both headers define the same parameter.
      def header
        @header ||= merge_headers!
      end

      # @return [String] the signing input for this signature.
      #
      # The protected header value is always used as it was received, so
      # moving a signature from one token to another with a shifted protected
      # header cannot be verified.
      def signing_input(encoded_payload)
        [encoded_protected_header || '', encoded_payload].join('.')
      end

      # Validates the structural rules independent of any caller policy:
      # protected/unprotected headers must be JSON objects and must not share
      # parameter names.
      #
      # @return [void]
      # @raise [JWT::MalformedTokenError] if the signature is structurally invalid.
      def validate!
        raise ::JWT::MalformedTokenError, 'Signature is missing the protected header' unless encoded_protected_header
        raise ::JWT::MalformedTokenError, 'Signature is missing the signature value' unless encoded_signature
        raise ::JWT::MalformedTokenError, 'Protected header is not a JSON object' unless protected_header.is_a?(::Hash)
        raise ::JWT::MalformedTokenError, 'Unprotected header is not a JSON object' if unprotected_header && !unprotected_header.is_a?(::Hash)
        raise ::JWT::MalformedTokenError, 'Signature header does not contain an algorithm' unless header['alg']

        nil
      end

      # @return [Hash] the JSON members used for the Flattened serialization.
      def to_flattened_hash
        {
          'protected' => encoded_protected_header,
          'header'    => unprotected_header,
          'signature' => encoded_signature
        }.compact
      end

      private

      def parse_protected_header
        return nil unless encoded_protected_header

        JWT::JSON.parse(::JWT::Base64.url_decode(encoded_protected_header))
      end

      def merge_headers!
        result = (unprotected_header || {}).dup
        (protected_header || {}).each do |name, value|
          raise ::JWT::MalformedTokenError, "Header parameter '#{name}' must not be present in both protected and unprotected headers" if result.key?(name)

          result[name] = value
        end
        result
      end
    end
  end
end
