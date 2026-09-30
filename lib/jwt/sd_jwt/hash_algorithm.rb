# frozen_string_literal: true

module JWT
  module SDJWT
    # RFC 9901 hash algorithms used for disclosure digests and sd_hash.
    class HashAlgorithm
      ALGORITHMS = {
        'sha-256' => OpenSSL::Digest::SHA256,
        'sha-384' => OpenSSL::Digest::SHA384,
        'sha-512' => OpenSSL::Digest::SHA512
      }.freeze

      attr_reader :name

      def self.find(name)
        name ||= 'sha-256'
        digest_class = ALGORITHMS[name]
        raise SDJWT::Error, "Unsupported SD-JWT hash algorithm: #{name}" unless digest_class

        new(name, digest_class)
      end

      def initialize(name, digest_class)
        @name = name
        @digest_class = digest_class
      end

      def digest(data)
        JWT::Base64.url_encode(@digest_class.digest(data))
      end
    end
  end
end
