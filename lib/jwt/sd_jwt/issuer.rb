# frozen_string_literal: true

require_relative 'constants'
require_relative 'disclosure'

module JWT
  module SDJWT
    # The result of issuing an SD-JWT.
    class IssuedCredential
      # @return [String] the signed issuer JWT.
      attr_reader :jwt

      # @return [Array<Disclosure>] all disclosures created for the credential.
      attr_reader :disclosures

      # @param jwt [String] the signed issuer JWT.
      # @param disclosures [Array<Disclosure>] the created disclosures.
      def initialize(jwt:, disclosures:)
        @jwt = jwt
        @disclosures = disclosures
      end

      # @return [String] the combined Issuer-SD-JWT serialization (RFC 9901 section 4).
      def to_s
        [jwt, *disclosures.map(&:encoded), ''].join(SEPARATOR)
      end
      alias sd_jwt to_s
    end

    # Issues SD-JWTs according to RFC 9901.
    #
    # The issuer starts with the full set of claims and marks individual object
    # members or array elements as selectively disclosable. Nested claims are
    # supported: when a whole object is disclosed after some of its members were
    # marked, the digests of the hidden members are carried inside the disclosed
    # value and can be revealed independently by the holder.
    #
    # @example
    #   issuer = JWT::SDJWT::Issuer.new({ name: 'Alice', age: 42, address: { country: 'US' } })
    #   issuer.disclose(:name)
    #   issuer.disclose('address', :country)
    #   issued = issuer.issue!(key: private_key, algorithm: 'ES256')
    class Issuer
      # @param payload [Hash] the full claims of the credential.
      # @param hash_algorithm [String] the hash algorithm to advertise in `_sd_alg`.
      def initialize(payload, hash_algorithm: DEFAULT_HASH_ALGORITHM)
        raise ::JWT::SDJWTIssueError, 'SD-JWT payload must be a JSON object' unless payload.is_a?(::Hash)

        Hasher.digest('', hash_algorithm) # validates the algorithm early
        ensure_no_reserved_keys!(payload)

        @payload = payload
        @hash_algorithm = hash_algorithm
        @requests = []
        @disclosures = []
        @issued = false
      end

      # @return [Hash] the full claims the issuer was initialized with.
      attr_reader :payload

      # Marks the object member or array element at the given path as selectively
      # disclosable.
      #
      # @param path [Array<String, Symbol, Integer>] the path to the claim.
      #   Strings/symbols address object members, integers address array elements.
      # @param salt [String, nil] a fixed salt (mainly useful for reproducible
      #   demos and tests). A random salt is generated when omitted.
      # @return [Issuer] self, so calls can be chained.
      # @raise [JWT::SDJWTIssueError] if the path does not exist or is invalid.
      def disclose(*path, salt: nil)
        salt = salt.call if salt.respond_to?(:call)
        request = normalize_and_validate_path(path, salt)
        @requests << request
        self
      end

      # Builds the signed issuer JWT from the marked claims.
      #
      # @param key [String, OpenSSL::PKey::PKey, JWT::JWK::KeyBase] the signing key.
      # @param algorithm [String] the JWS algorithm, e.g. `HS256` or `ES256`.
      # @param header_fields [Hash] additional JWS header fields.
      # @return [IssuedCredential]
      # @raise [JWT::SDJWTIssueError, JWT::EncodeError] if issuing fails.
      def issue!(key:, algorithm: 'HS256', header_fields: {})
        raise ::JWT::SDJWTIssueError, 'Credential already issued' if @issued

        sd_payload = build_sd_payload
        headers = { 'typ' => SD_JWT_TYPE }.merge(stringify(header_fields))

        token = ::JWT::Token.new(payload: sd_payload, header: headers)
        token.sign!(algorithm: algorithm, key: key)

        @issued = IssuedCredential.new(jwt: token.jwt, disclosures: @disclosures)
      end

      private

      def normalize_and_validate_path(path, salt)
        raise ::JWT::SDJWTIssueError, 'A disclosure path must not be empty' if path.empty?

        normalized = path.map { |segment| normalize_segment(segment) }
        resolve_path(normalized)

        if @requests.any? { |request| request[0] == normalized }
          raise ::JWT::SDJWTIssueError, "Claim at #{normalized.inspect} is already marked for disclosure"
        end

        raise ::JWT::SDJWTIssueError, 'Salt must be a String when provided' unless salt.nil? || salt.is_a?(::String)

        [normalized, salt]
      end

      def normalize_segment(segment)
        case segment
        when ::Symbol, ::String
          normalize_name_segment(segment.to_s)
        when ::Integer
          raise ::JWT::SDJWTIssueError, 'Array indices must not be negative' if segment.negative?

          segment
        else
          raise ::JWT::SDJWTIssueError, "Invalid disclosure path segment: #{segment.inspect}"
        end
      end

      def normalize_name_segment(name)
        raise ::JWT::SDJWTIssueError, 'Claim names must not be empty' if name.empty?
        if RESERVED_CLAIM_NAMES.include?(name)
          raise ::JWT::SDJWTIssueError, "Claim name '#{name}' is reserved"
        end

        name
      end

      def resolve_path(path)
        node = @payload
        path.each do |segment|
          if segment.is_a?(::String)
            unless node.is_a?(::Hash) && (node.key?(segment) || node.key?(segment.to_sym))
              raise ::JWT::SDJWTIssueError, "No object member found at #{path.inspect}"
            end

            node = node.key?(segment) ? node[segment] : node[segment.to_sym]
          else
            raise ::JWT::SDJWTIssueError, "No array element found at #{path.inspect}" unless node.is_a?(::Array) && segment < node.length

            node = node[segment]
          end
        end
      end

      def build_sd_payload
        sd_payload = sanitize(@payload)

        # Deepest claims first, and higher array indices before lower ones, so
        # that removing an element never shifts an index that is still pending.
        requests = @requests.sort { |a, b| compare_requests(a[0], b[0]) }

        requests.each do |path, salt|
          create_disclosure(sd_payload, path, salt)
        end

        @disclosures.sort_by! { |disclosure| disclosure_path_sort_key(disclosure.path) }
        sd_payload['_sd_alg'] = @hash_algorithm
        sd_payload
      end

      # Orders disclosures in a natural traversal order: parents before
      # children, object members before array elements, array indices ascending.
      def disclosure_path_sort_key(path)
        path.map.with_index do |segment, index|
          [segment.is_a?(::Integer) ? 1 : 0, segment.is_a?(::Integer) ? segment : segment.to_s, index]
        end
      end

      def compare_requests(path_a, path_b)
        depth = path_b.length <=> path_a.length
        return depth unless depth.zero?

        path_a.each_index do |i|
          a = path_a[i]
          b = path_b[i]
          next if a == b

          if a.is_a?(::Integer) && b.is_a?(::Integer)
            return b <=> a
          end

          return a.to_s <=> b.to_s
        end
        0
      end

      def create_disclosure(sd_payload, path, salt)
        *parent_path, last = path
        container = parent_path.empty? ? sd_payload : navigate(sd_payload, parent_path)

        if last.is_a?(::Integer)
          value = container.delete_at(last)
          disclosure = Disclosure.array_element(value, salt, path: path)
          container.insert(last, { ELLIPSIS => disclosure.digest(@hash_algorithm) })
        else
          value = container.delete(last)
          disclosure = Disclosure.property(last, value, salt, path: path)
          (container[SD_KEY] ||= []) << disclosure.digest(@hash_algorithm)
          container[SD_KEY].sort!
        end

        @disclosures << disclosure
      end

      def navigate(sd_payload, path)
        path.reduce(sd_payload) do |node, segment|
          if segment.is_a?(::Integer)
            # After an array element has been disclosed it is represented by a
            # one-key placeholder object; continue inside its disclosed value.
            element = node.fetch(segment)
            if element.is_a?(::Hash) && element.key?(ELLIPSIS)
              find_disclosed_value(element.fetch(ELLIPSIS))
            else
              element
            end
          else
            node.fetch(segment)
          end
        end
      end

      # Looks up the (possibly nested) value carried by an already created
      # disclosure with the given digest.
      def find_disclosed_value(digest)
        disclosure = @disclosures.find { |entry| entry.digest(@hash_algorithm) == digest }
        raise ::JWT::SDJWTIssueError, 'Internal error: could not resolve disclosed array element' unless disclosure

        disclosure.value
      end

      def sanitize(node)
        case node
        when ::Hash
          node.each_with_object({}) do |(key, value), result|
            result[key.to_s] = sanitize(value)
          end
        when ::Array
          node.map { |value| sanitize(value) }
        else
          node
        end
      end

      def ensure_no_reserved_keys!(payload)
        walk(payload) do |visited_path|
          key = visited_path.last
          next unless RESERVED_CLAIM_NAMES.include?(key)

          raise ::JWT::SDJWTIssueError, "Claim name '#{key}' is reserved by the SD-JWT specification"
        end
      end

      def walk(node, visited_path = [], &block)
        case node
        when ::Hash
          node.each do |key, value|
            current = visited_path + [key.to_s]
            block.call(current)
            walk(value, current, &block)
          end
        when ::Array
          node.each_with_index { |value, index| walk(value, visited_path + [index], &block) }
        end
      end

      def stringify(hash)
        hash.each_with_object({}) { |(key, value), result| result[key.to_s] = value }
      end
    end
  end
end
