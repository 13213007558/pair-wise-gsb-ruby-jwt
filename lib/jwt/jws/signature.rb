# frozen_string_literal: true

module JWT
  module JWS
    # Describes one signature of a JWS JSON Serialization.
    #
    # A signature is produced by signing the shared payload with one
    # independent key. The same key used twice never creates two independent
    # signers (see {JWT::JWS.verify}).
    class Signature
      # @return [String] the algorithm used to produce the signature.
      attr_reader :algorithm

      # @return [String, JWT::JWK::KeyBase] the key used to produce the signature.
      attr_reader :key

      # @return [String, nil] the key id, copied into the protected header.
      attr_reader :kid

      # @return [Hash] additional protected header parameters.
      attr_reader :protected_header

      # @return [Hash] unprotected ("header") parameters.
      attr_reader :unprotected_header

      # Builds a Signature from keyword arguments or a Hash.
      #
      # @param spec [Hash, JWT::JWS::Signature] the signature specification.
      # @option spec [String] :algorithm the signing algorithm.
      # @option spec [String, JWT::JWK::KeyBase] :key the signing key.
      # @option spec [String] :kid optional key id.
      # @option spec [Hash] :protected_header additional protected parameters.
      # @option spec [Hash] :header unprotected parameters.
      # @return [JWT::JWS::Signature]
      def self.from(spec)
        return spec.dup if spec.is_a?(self)

        new(**spec.transform_keys(&:to_sym))
      end

      # @see .from
      def initialize(algorithm:, key:, kid: nil, protected_header: nil, header: nil, unprotected_header: nil)
        raise ::JWT::EncodeError, 'An algorithm must be specified' if algorithm.nil? || algorithm.to_s.empty?
        raise ::JWT::EncodeError, 'A signing key must be specified' if key.nil?

        @algorithm = algorithm.to_s
        @key = key
        @kid = kid
        @protected_header = stringify(protected_header)
        @unprotected_header = stringify(header || unprotected_header)
      end

      # Identity of the independent signer. Two signatures produced with the
      # same key share the same identity even when different headers are used.
      #
      # @return [Array]
      def identity
        @identity ||= [key.class, key_identity]
      end

      # Returns a copy of the signature.
      #
      # @return [JWT::JWS::Signature]
      def dup
        self.class.new(algorithm: algorithm,
                       key: key,
                       kid: kid,
                       protected_header: protected_header.dup,
                       header: unprotected_header.dup)
      end

      private

      def key_identity
        key.respond_to?(:object_id) ? key.object_id : key
      end

      def stringify(hash)
        (hash || {}).each_with_object({}) do |(name, value), result|
          result[name.to_s] = value
        end
      end
    end
  end
end
