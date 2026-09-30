# frozen_string_literal: true

module JWT
  module JWS
    # Produces and parses JWS JSON Serializations (RFC 7515, sections 7.2.1 and 7.2.2).
    #
    # @api private
    class Serializer
      # @param payload [Object] the payload shared by every signature.
      # @param signatures [Array<JWT::JWS::Signature>] the signatures to produce.
      def initialize(payload, signatures)
        @payload = payload
        @signatures = signatures
      end

      # Builds the JWS JSON Serialization as a Hash.
      #
      # @param flattened [Boolean] return the Flattened syntax when there is a single signature.
      # @return [Hash]
      def serialize(flattened:)
        validate_payload!

        encoded_payload = Base64.url_encode(JSON.generate(@payload))
        members = @signatures.map { |signature| sign(signature, encoded_payload) }

        if flattened
          raise ::JWT::EncodeError, 'Flattened JSON Serialization supports exactly one signature' unless members.size == 1

          { 'payload' => encoded_payload }.merge!(members.first)
        else
          { 'payload' => encoded_payload, 'signatures' => members }
        end
      end

      class << self
        # Parses a JWS JSON Serialization given as a Hash or a JSON String.
        #
        # @param data [Hash, String] the serialized JWS.
        # @return [Array] the encoded payload and the array of raw signature members.
        # @raise [JWT::MalformedTokenError] if the structure is not a valid JWS JSON Serialization.
        def parse(data)
          parsed = data.is_a?(::String) ? parse_json(data) : data
          raise ::JWT::MalformedTokenError, 'JWS JSON Serialization must be a JSON object' unless parsed.is_a?(::Hash)

          encoded_payload = parsed['payload']
          raise ::JWT::MalformedTokenError, 'JWS JSON Serialization is missing the payload' unless encoded_payload.is_a?(::String)

          [encoded_payload, extract_members(parsed)]
        end

        private

        def parse_json(data)
          ::JSON.parse(data)
        rescue ::JSON::ParserError
          raise ::JWT::MalformedTokenError, 'Invalid JWS JSON Serialization encoding'
        end

        def extract_members(hash)
          if hash.key?('signatures')
            members = hash['signatures']
            unless members.is_a?(::Array) && !members.empty?
              raise ::JWT::MalformedTokenError, 'The signatures member must be a non-empty array'
            end

            members.map { |member| validate_general_member(member) }
          else
            [validate_flattened_member(hash)]
          end
        end

        def validate_general_member(member)
          raise ::JWT::MalformedTokenError, 'Every signature must be a JSON object' unless member.is_a?(::Hash)
          raise ::JWT::MalformedTokenError, 'The payload member must not be repeated in a signature' if member.key?('payload')

          raw_member(member)
        end

        def validate_flattened_member(hash)
          raw_member(hash)
        end

        def raw_member(member)
          {
            'protected' => member['protected'],
            'header' => member['header'],
            'signature' => member['signature']
          }
        end
      end

      private

      def validate_payload!
        raise ::JWT::EncodeError, 'Payload must be specified' if @payload.nil?
        raise ::JWT::EncodeError, 'At least one signature must be specified' if @signatures.empty?
      end

      def sign(signature, encoded_payload)
        custom_protected = custom_protected_header(signature)
        ensure_no_header_overlap!(custom_protected, signature.unprotected_header)
        protected_header = custom_protected.merge(JWA.resolve(signature.algorithm).header) { |_name, custom, _generated| custom }

        encoded_header = Base64.url_encode(JSON.generate(protected_header))
        signing_input = [encoded_header, encoded_payload].join('.')
        signer = JWA.create_signer(algorithm: signature.algorithm, key: signature.key)
        signature_bytes = signer.sign(data: signing_input)

        member = { 'protected' => encoded_header, 'signature' => Base64.url_encode(signature_bytes) }
        member['header'] = signature.unprotected_header unless signature.unprotected_header.empty?
        member
      end

      def custom_protected_header(signature)
        header = signature.protected_header.dup
        if signature.kid
          header['kid'] ||= signature.kid
        end
        header
      end

      def ensure_no_header_overlap!(protected_header, unprotected_header)
        overlap = protected_header.keys & unprotected_header.keys
        return if overlap.empty?

        raise ::JWT::EncodeError, "Protected and unprotected headers must not share parameters: #{overlap.join(', ')}"
      end
    end
  end
end
