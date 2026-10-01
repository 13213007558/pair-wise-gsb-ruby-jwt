# frozen_string_literal: true

module JWT
  # The base error class for all JWT errors.
  class Error < StandardError; end

  # The EncodeError class is raised when there is an error encoding a JWT.
  class EncodeError < Error; end

  # The historical grouping of every error that is not an encoding error. Every
  # error class below is a descendant, so `rescue JWT::DecodeError` keeps its
  # original meaning.
  #
  # @deprecated Use {JWT::Error}, {JWT::TokenError} or a more specific error class instead.
  class DecodeError < Error; end

  # The TokenError class is the base class for all errors related to token processing.
  class TokenError < DecodeError; end

  # The MalformedTokenError class is raised when the token is structurally invalid.
  class MalformedTokenError < TokenError; end

  # The Base64DecodeError class is raised when there is an error decoding a Base64-encoded string.
  class Base64DecodeError < MalformedTokenError; end

  # The StrictDecodingError class is raised when strict JSON decoding is
  # enabled and the header or payload JSON contains duplicate object keys or
  # exceeds the configured size or nesting depth limits.
  #
  # For duplicate keys the error carries the JSON path of the duplicate
  # member and the byte offsets of both occurrences of the key within the
  # decoded JSON segment.
  class StrictDecodingError < MalformedTokenError
    # @return [String, nil] the JSON path of the duplicate key (e.g. "$.iss").
    attr_reader :path
    # @return [String, nil] the duplicate key after JSON string decoding.
    attr_reader :key
    # @return [Integer, nil] the byte offset of the first occurrence of the key.
    attr_reader :first_offset
    # @return [Integer, nil] the byte offset of the second occurrence of the key.
    attr_reader :second_offset

    def initialize(message = nil, path: nil, key: nil, first_offset: nil, second_offset: nil)
      @path = path
      @key = key
      @first_offset = first_offset
      @second_offset = second_offset
      super(message)
    end
  end

  # The SignatureError class is the base class for signature and algorithm related errors.
  class SignatureError < TokenError; end

  # The VerificationError class is raised when the signature of a token does not
  # match the one calculated from the signing input.
  class VerificationError < SignatureError; end

  # The VerificationKeyError class is raised when the key or algorithm given for
  # verification cannot be used, as opposed to a signature that does not match.
  class VerificationKeyError < VerificationError; end

  # The IncorrectAlgorithm class is raised when the JWT algorithm is incorrect.
  class IncorrectAlgorithm < SignatureError; end

  # The UnsupportedEcdsaCurve class is raised when the ECDSA curve is unsupported.
  class UnsupportedEcdsaCurve < IncorrectAlgorithm; end

  # The ClaimValidationError class is the base class for all claim validation errors.
  class ClaimValidationError < TokenError; end

  # The ExpiredSignature class is raised when the JWT token has expired.
  class ExpiredSignature < ClaimValidationError; end

  # The ImmatureSignature class is raised when the JWT token is not yet valid (nbf).
  class ImmatureSignature < ClaimValidationError; end

  # The InvalidIssuerError class is raised when the JWT issuer is invalid.
  class InvalidIssuerError < ClaimValidationError; end

  # The InvalidIatError class is raised when the JWT issued at (iat) claim is invalid.
  class InvalidIatError < ClaimValidationError; end

  # The InvalidAudError class is raised when the JWT audience (aud) claim is invalid.
  class InvalidAudError < ClaimValidationError; end

  # The InvalidSubError class is raised when the JWT subject (sub) claim is invalid.
  class InvalidSubError < ClaimValidationError; end

  # The InvalidCritError class is raised when the JWT crit header is invalid.
  class InvalidCritError < ClaimValidationError; end

  # The InvalidJtiError class is raised when the JWT ID (jti) claim is invalid.
  class InvalidJtiError < ClaimValidationError; end

  # The InvalidPayload class is raised when the JWT payload is invalid.
  class InvalidPayload < ClaimValidationError; end

  # The MissingRequiredClaim class is raised when a required claim is missing from the JWT.
  class MissingRequiredClaim < ClaimValidationError; end

  # The JWKError class is raised when there is an error with the JSON Web Key (JWK).
  class JWKError < DecodeError; end

  # Raised when a JWK uses a key type (kty) that this library does not support.
  class UnsupportedKeyType < JWKError; end
end
