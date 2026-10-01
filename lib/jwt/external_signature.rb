# frozen_string_literal: true

require 'base64'

module JWT
  # Normalizes signatures produced by external signers (HSMs, KMS services,
  # approval workflows) into the exact byte format required by JWS.
  #
  # External signers differ in how they return signatures:
  #
  # * RSA and RSA-PSS signatures are single byte strings, but are often
  #   transported Base64 or Base64URL encoded.
  # * ECDSA signatures are commonly returned as ASN.1 DER encoded
  #   sequences (for example by OpenSSL, PKCS#11 and many HSMs), while JWS
  #   requires the raw R || S concatenation. Both forms, optionally Base64
  #   or Base64URL encoded, are accepted.
  #
  # @api private
  module ExternalSignature
    module_function

    # Normalizes an externally produced signature into JWS format.
    #
    # @param jwa [JWA::SigningAlgorithm] the resolved algorithm of the request.
    # @param signature [String] the signature as returned by the external signer.
    # @param verification_key [Object] the public key the signature is checked against.
    # @return [String] the signature in JWS format.
    def normalize(jwa:, signature:, verification_key:)
      raise VerificationError, 'Signature must be a String' unless signature.is_a?(String)

      binary = decode_transport(signature)

      return normalize_ecdsa(binary, verification_key) if jwa.is_a?(JWA::Ecdsa)

      binary
    end

    # Decodes Base64/Base64URL transport encoding, if present. Signatures
    # that already are in the expected raw size are kept as-is, everything
    # else that strictly decodes as Base64 is decoded.
    def decode_transport(signature)
      decoded = strict_base64_decode(signature)
      decoded || signature
    end

    def strict_base64_decode(string)
      ::Base64.urlsafe_decode64(string)
    rescue ArgumentError
      begin
        ::Base64.strict_decode64(string)
      rescue ArgumentError
        nil
      end
    end

    # Brings an ECDSA signature into the raw R || S form. Accepts the raw
    # form itself and the ASN.1 DER form commonly returned by external
    # signers.
    def normalize_ecdsa(signature, verification_key)
      byte_size = ecdsa_byte_size(verification_key)

      # Without a known curve the key cannot be used at all; pass the
      # signature through so verification raises the proper key error.
      return signature unless byte_size
      return signature if signature.bytesize == 2 * byte_size

      der = der_to_raw(signature, byte_size)
      return der if der

      raise VerificationError, 'ECDSA signature is neither in raw R || S nor in ASN.1 DER format'
    end

    def ecdsa_byte_size(verification_key)
      group = case verification_key
              when ::OpenSSL::PKey::EC then verification_key.group
              when ::OpenSSL::PKey::EC::Point then verification_key.group
              end
      group && (group.degree + 7) / 8
    end

    # Transcodes an ASN.1 DER encoded ECDSA signature into raw R || S form.
    # Returns nil when the input is not a well formed DER signature.
    def der_to_raw(signature, byte_size)
      asn1 = ::OpenSSL::ASN1.decode(signature)
      return nil unless asn1.is_a?(::OpenSSL::ASN1::Sequence) && asn1.value.size == 2

      r, s = asn1.value
      return nil unless r.is_a?(::OpenSSL::ASN1::Integer) && s.is_a?(::OpenSSL::ASN1::Integer)
      return nil unless byte_size

      r.value.to_s(2).rjust(byte_size, "\x00") + s.value.to_s(2).rjust(byte_size, "\x00")
    rescue ::OpenSSL::ASN1::ASN1Error
      nil
    end
  end
end
