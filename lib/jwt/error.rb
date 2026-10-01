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

  # The JSONParseError class is raised when a JWT header or payload segment is
  # not valid JSON. In strict mode it also carries the byte position at which
  # parsing failed.
  class JSONParseError < MalformedTokenError
    # @return [Integer, nil] the zero-based byte position of the failure within the JSON segment.
    attr_reader :position

    def initialize(message = 'Invalid JSON encoding', position: nil)
      @position = position
      super(message)
    end
  end

  # The DuplicateJSONKeyError class is raised in strict JSON decoding mode when
  # an object contains two members with the same name, e.g. two "iss" claims.
  class DuplicateJSONKeyError < JSONParseError
    # @return [String] the JSON path of the duplicate member within its segment (e.g. "$.foo[0].iss").
    attr_reader :path
    # @return [String] the decoded member name that appeared more than once.
    attr_reader :key
    # @return [Integer] the zero-based byte position of the first member's key.
    attr_reader :first_position
    # @return [Integer] the zero-based byte position of the duplicate member's key.
    attr_reader :duplicate_position

    def initialize(path:, key:, first_position:, duplicate_position:) # rubocop:disable Metrics/ParameterLists
      @path               = path
      @key                = key
      @first_position     = first_position
      @duplicate_position = duplicate_position
      super(
        "Duplicate member \"#{key}\" in JSON object at #{path}: " \
        "keys at byte positions #{first_position} and #{duplicate_position}",
        position: duplicate_position
      )
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
