# frozen_string_literal: true

require 'base64'

module SpecSupport
  # Simulates an isolated signing party (e.g. an offline HSM) that never shares
  # its private key with the token issuing system.
  #
  # The signer only receives the serialized signing request, reads the fixed
  # algorithm and signing input, performs the signature locally with OpenSSL and
  # returns the encoded signature bytes. Different HSM vendors return signatures
  # in different encodings, which can be selected with the +encoding+ option.
  class ExternalSigner
    ECDSA_DIGEST = {
      'ES256' => 'SHA256',
      'ES256K' => 'SHA256',
      'ES384' => 'SHA384',
      'ES512' => 'SHA512'
    }.freeze

    ECDSA_RAW_HALF_LENGTH = {
      'ES256' => 32,
      'ES256K' => 32,
      'ES384' => 48,
      'ES512' => 66
    }.freeze

    # @param private_key [OpenSSL::PKey::RSA, OpenSSL::PKey::EC] the isolated private key.
    # @param encoding [:raw, :base64, :base64url] the wire encoding of the signature.
    # @param ecdsa_format [:der, :raw] whether ECDSA signatures are DER or fixed length raw R || S.
    def initialize(private_key:, encoding: :raw, ecdsa_format: :der)
      @private_key = private_key
      @encoding = encoding
      @ecdsa_format = ecdsa_format
    end

    # @return [OpenSSL::PKey::RSA, OpenSSL::PKey::EC] the matching public key.
    def public_key
      @private_key
    end

    # Signs the request exactly as an external system would: based solely on
    # the serialized request it receives.
    #
    # @param request [String, Hash, JWT::SigningRequest] the serialized signing request.
    # @return [String] the encoded signature.
    def sign(request)
      request = parse(request)
      signature = raw_signature(request.fetch('alg'), request.fetch('signing_input'))
      encode(signature)
    end

    private

    def parse(request)
      return JSON.parse(request) if request.is_a?(String)
      return request.transform_keys(&:to_s) if request.is_a?(Hash)

      JSON.parse(request.to_json)
    end

    def raw_signature(alg, data)
      case alg
      when /\ARS/
        @private_key.sign(OpenSSL::Digest.new(alg.sub('RS', 'SHA')), data)
      when /\APS/
        digest = alg.sub('PS', 'sha')
        @private_key.sign_pss(digest, data, salt_length: :digest, mgf1_hash: digest)
      when /\AES/
        der = @private_key.dsa_sign_asn1(OpenSSL::Digest.digest(ECDSA_DIGEST.fetch(alg), data))
        @ecdsa_format == :raw ? der_to_raw(der, alg) : der
      else
        raise "Unsupported external signing algorithm #{alg}"
      end
    end

    def der_to_raw(der, alg)
      byte_size = ECDSA_RAW_HALF_LENGTH.fetch(alg)
      OpenSSL::ASN1.decode(der).value.map { |v| v.value.to_s(2).rjust(byte_size, "\x00") }.join
    end

    def encode(signature)
      case @encoding
      when :raw then signature
      when :base64 then ::Base64.strict_encode64(signature)
      when :base64url then ::Base64.urlsafe_encode64(signature, padding: false)
      else raise "Unknown encoding #{@encoding}"
      end
    end
  end
end
