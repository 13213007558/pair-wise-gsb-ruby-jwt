# frozen_string_literal: true

require 'json'
require_relative 'error'

module JWT
  # JSON parsing and generation used for JWT header and payload segments.
  # @api private
  class JSON
    # Maximum size in bytes of a JSON segment parsed in strict mode.
    MAX_DOCUMENT_SIZE = 10 * 1024 * 1024

    # Maximum nesting depth of a JSON document parsed in strict mode.
    MAX_NESTING_DEPTH = 100

    class << self
      # Serializes a Ruby object to JSON. Always called on trusted data that the
      # library itself constructed, so a re-serialized document is never fed
      # back into signature verification.
      def generate(data)
        ::JSON.generate(data)
      end

      # Parses a JSON document.
      #
      # In strict mode the document is parsed by a decoder that rejects, at any
      # nesting level:
      #
      # * objects containing duplicate member names ("iss" and "\u0069iss" are
      #   the same member),
      # * documents exceeding the configured size or nesting limits,
      # * any JSON construct not allowed by RFC 8259.
      #
      # @param data [String] the JSON document.
      # @param strict [Boolean] whether to use the strict decoder.
      # @param max_size [Integer] maximum document size in bytes (strict mode only).
      # @param max_depth [Integer] maximum nesting depth (strict mode only).
      # @return [Object] the parsed document.
      # @raise [JWT::JSONParseError] if the document cannot be parsed (strict mode).
      # @raise [JSON::ParserError] if the document cannot be parsed (default mode).
      def parse(data, strict: false, max_size: MAX_DOCUMENT_SIZE, max_depth: MAX_NESTING_DEPTH)
        return StrictParser.new(data, max_size: max_size, max_depth: max_depth).parse if strict

        ::JSON.parse(data)
      end
    end

    # A hand-rolled RFC 8259 compliant JSON decoder.
    #
    # The decoder scans the raw bytes itself, which is what makes duplicate
    # member detection possible: a Hash based decode silently overwrites the
    # first member. Keys are compared after unescaping, so "iss" written
    # literally and "iss" written as a Unicode escape collide. Braces and
    # quotes inside string values are only ever seen as ordinary characters.
    #
    # @api private
    class StrictParser
      ESCAPES = {
        '"' => '"',
        '\\' => '\\',
        '/' => '/',
        'b' => "\b",
        'f' => "\f",
        'n' => "\n",
        'r' => "\r",
        't' => "\t"
      }.freeze

      def initialize(data, max_size:, max_depth:)
        @data = data.is_a?(String) ? data.dup : data.to_s
        @data.force_encoding(Encoding::BINARY)
        @pos = 0
        @max_size = max_size
        @max_depth = max_depth
        @path = []
      end

      def parse
        raise JSONParseError.new('JSON document is empty', position: 0) if @data.empty?
        if @data.bytesize > @max_size
          raise JSONParseError.new(
            "JSON document of #{@data.bytesize} bytes exceeds the maximum size of #{@max_size} bytes",
            position: @max_size
          )
        end

        skip_whitespace
        value = parse_value(depth: 0)
        skip_whitespace
        unless @pos == @data.bytesize
          raise JSONParseError.new('Unexpected bytes after JSON value', position: @pos)
        end

        value
      end

      private

      def parse_value(depth:)
        check_depth!(depth)
        skip_whitespace
        raise JSONParseError.new('Unexpected end of JSON document', position: @pos) if @pos >= @data.bytesize

        byte = @data.getbyte(@pos)
        case byte
        when 0x7B then parse_object(depth) # {
        when 0x5B then parse_array(depth)  # [
        when 0x22 then parse_string        # "
        when 0x74, 0x66, 0x6E then parse_literal(byte) # t, f, n
        else
          if number_start?(byte)
            parse_number
          else
            raise JSONParseError.new('Unexpected byte while parsing JSON value', position: @pos)
          end
        end
      end

      def parse_object(depth)
        consume_byte!(0x7B)
        object = {}
        skip_whitespace
        if peek_byte == 0x7D
          @pos += 1
          return object
        end

        member_positions = {}
        loop do
          skip_whitespace
          unless peek_byte == 0x22
            raise JSONParseError.new('Expected an object member key', position: @pos)
          end

          key_start = @pos
          key = parse_string
          if member_positions.key?(key)
            raise DuplicateJSONKeyError.new(
              path: current_path_with(key),
              key: key,
              first_position: member_positions[key],
              duplicate_position: key_start
            )
          end
          member_positions[key] = key_start

          skip_whitespace
          expect_byte!(0x3A, 'Expected a colon after object member key')
          @path << key
          begin
            object[key] = parse_value(depth: depth + 1)
          ensure
            @path.pop
          end

          skip_whitespace
          byte = read_byte!
          break if byte == 0x7D # }

          raise JSONParseError.new('Expected a comma or closing brace in object', position: @pos - 1) unless byte == 0x2C
        end

        object
      end

      def parse_array(depth)
        consume_byte!(0x5B)
        array = []
        skip_whitespace
        if peek_byte == 0x5D
          @pos += 1
          return array
        end

        loop do
          @path << array.size
          begin
            array << parse_value(depth: depth + 1)
          ensure
            @path.pop
          end

          skip_whitespace
          byte = read_byte!
          break if byte == 0x5D # ]

          raise JSONParseError.new('Expected a comma or closing bracket in array', position: @pos - 1) unless byte == 0x2C
        end

        array
      end

      def parse_literal(first_byte)
        case first_byte
        when 0x74 # true
          read_literal!('true', true)
        when 0x66 # false
          read_literal!('false', false)
        else       # null
          read_literal!('null', nil)
        end
      end

      def read_literal!(literal, value)
        literal.each_byte do |expected|
          byte = read_byte!
          raise JSONParseError.new("Invalid literal, expected #{literal}", position: @pos - 1) unless byte == expected
        end
        value
      end

      NUMBER_MATCH = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/n
      private_constant(:NUMBER_MATCH)

      def parse_number
        match = NUMBER_MATCH.match(@data, @pos)
        if match.nil? || match.begin(0) != @pos
          raise JSONParseError.new('Expected a JSON number', position: @pos)
        end

        raw = match[0]
        @pos += raw.bytesize

        # A digit or dot left immediately after the match means a malformed
        # number such as "01" or "1.2.3", whose prefix the grammar still matches.
        following = peek_byte
        if following && (digit_byte?(following) || following == 0x2E)
          raise JSONParseError.new('Invalid JSON number', position: @pos)
        end

        raw.include?('.') || raw.match?(/[eE]/) ? Float(raw) : Integer(raw, 10)
      end

      def number_start?(byte)
        (byte >= 0x30 && byte <= 0x39) || byte == 0x2D # 0-9 or -
      end

      def digit_byte?(byte)
        byte && byte >= 0x30 && byte <= 0x39
      end

      SPECIAL_STRING_BYTES = /[\\"\x00-\x1f]/n # quote, backslash or a control character
      private_constant(:SPECIAL_STRING_BYTES)

      def parse_string
        consume_byte!(0x22)
        buffer = +''.b

        loop do
          special = @data.index(SPECIAL_STRING_BYTES, @pos)
          raise JSONParseError.new('Unterminated string', position: @data.bytesize) if special.nil?

          buffer << @data.byteslice(@pos...special)
          @pos = special
          byte = next_string_byte
          if byte == 0x22 # closing quote
            result = buffer.force_encoding(Encoding::UTF_8)
            unless result.valid_encoding?
              raise JSONParseError.new('Invalid UTF-8 encoding in string', position: special)
            end

            return result
          elsif byte == 0x5C # backslash
            buffer << read_escape
          else
            raise JSONParseError.new('Unescaped control character in string', position: @pos - 1)
          end
        end
      end

      # Returns the byte following the current position and advances the cursor.
      def next_string_byte
        raise JSONParseError.new('Unterminated string', position: @data.bytesize) if @pos >= @data.bytesize

        byte = @data.getbyte(@pos)
        @pos += 1
        byte
      end

      def read_escape
        byte = next_string_byte
        case byte
        when 0x75 # u
          code = read_hex4
          if (0xD800..0xDBFF).cover?(code) # high surrogate, must be followed by a low surrogate
            unless next_string_byte == 0x5C && next_string_byte == 0x75
              raise JSONParseError.new('Invalid Unicode escape: high surrogate without low surrogate', position: @pos)
            end
            low = read_hex4
            unless (0xDC00..0xDFFF).cover?(low)
              raise JSONParseError.new('Invalid Unicode escape: expected low surrogate', position: @pos - 6)
            end
            code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)
          elsif (0xDC00..0xDFFF).cover?(code)
            raise JSONParseError.new('Invalid Unicode escape: low surrogate without high surrogate', position: @pos)
          end
          [code].pack('U').b
        else
          escaped = byte.chr
          unless ESCAPES.key?(escaped)
            raise JSONParseError.new("Invalid escape sequence \\#{escaped}", position: @pos - 1)
          end

          ESCAPES[escaped].b
        end
      end

      def read_hex4
        hex = @data.byteslice(@pos, 4)
        raise JSONParseError.new('Truncated Unicode escape', position: @pos) unless hex&.bytesize == 4 && hex.match?(/\A[0-9a-fA-F]{4}\z/)

        @pos += 4
        hex.to_i(16)
      end

      WHITESPACE_MATCH = /[ \t\n\r]*/n
      private_constant(:WHITESPACE_MATCH)

      def skip_whitespace
        match = WHITESPACE_MATCH.match(@data, @pos)
        @pos = match&.end(0) || @pos
      end

      def peek_byte
        @pos < @data.bytesize ? @data.getbyte(@pos) : nil
      end

      def read_byte!
        raise JSONParseError.new('Unexpected end of JSON document', position: @data.bytesize) if @pos >= @data.bytesize

        byte = @data.getbyte(@pos)
        @pos += 1
        byte
      end

      def consume_byte!(expected)
        byte = read_byte!
        raise JSONParseError.new('Unexpected byte', position: @pos - 1) unless byte == expected
      end

      def expect_byte!(expected, message)
        byte = read_byte!
        raise JSONParseError.new(message, position: @pos - 1) unless byte == expected
      end

      def check_depth!(depth)
        return unless depth >= @max_depth

        raise JSONParseError.new("JSON document nesting depth exceeds the maximum of #{@max_depth}", position: @pos)
      end

      def current_path_with(key)
        format_path(@path + [key])
      end

      def format_path(segments)
        segments.each_with_object(+'$') do |segment, path|
          if segment.is_a?(Integer)
            path << "[#{segment}]"
          elsif segment.match?(/\A[A-Za-z_][A-Za-z0-9_]*\z/)
            path << '.' << segment
          else
            path << '[' << ::JSON.generate(segment) << ']'
          end
        end
      end
    end
  end
end
