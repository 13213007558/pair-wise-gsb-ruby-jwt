# frozen_string_literal: true

module JWT
  # StrictJSON is a strict JSON parser used when strict decoding is enabled.
  #
  # Unlike the standard JSON parser it:
  #
  # * rejects objects containing duplicate keys at any nesting level. Keys are
  #   compared after JSON string decoding, so a key written with Unicode
  #   escapes (e.g. <tt>"\u0069ss"</tt>) is considered a duplicate of the
  #   same key written literally (<tt>"iss"</tt>);
  # * reports the JSON path of the duplicate and the byte offsets of both
  #   occurrences of the key;
  # * enforces a maximum input size and a maximum nesting depth.
  #
  # Duplicate keys and limit violations raise {JWT::StrictDecodingError},
  # malformed JSON raises {StrictJSON::ParserError} which is converted to
  # {JWT::MalformedTokenError} by the caller.
  #
  # @api private
  class StrictJSON
    # Raised when the input is not valid JSON. Converted to
    # {JWT::MalformedTokenError} by the caller.
    class ParserError < StandardError; end

    # Default maximum size of a JSON segment in bytes.
    DEFAULT_MAX_SIZE = 64 * 1024
    # Default maximum nesting depth of objects and arrays.
    DEFAULT_MAX_DEPTH = 32

    BACKSLASH = 0x5C
    QUOTE = 0x22
    OPEN_BRACE = 0x7B
    CLOSE_BRACE = 0x7D
    OPEN_BRACKET = 0x5B
    CLOSE_BRACKET = 0x5D
    COMMA = 0x2C
    COLON = 0x3A
    MINUS = 0x2D
    PLUS = 0x2B
    DOT = 0x2E
    ZERO = 0x30

    private_constant :BACKSLASH, :QUOTE, :OPEN_BRACE, :CLOSE_BRACE,
                     :OPEN_BRACKET, :CLOSE_BRACKET, :COMMA, :COLON,
                     :MINUS, :PLUS, :DOT, :ZERO

    class << self
      # Parses the given JSON string strictly.
      #
      # @param data [String] the JSON document to parse.
      # @param max_size [Integer] maximum allowed size of the document in bytes.
      # @param max_depth [Integer] maximum allowed nesting depth.
      # @return [Object] the parsed document.
      # @raise [JWT::StrictDecodingError] on duplicate keys or exceeded limits.
      # @raise [StrictJSON::ParserError] on malformed JSON.
      def parse(data, max_size: DEFAULT_MAX_SIZE, max_depth: DEFAULT_MAX_DEPTH)
        new(data, max_size: max_size, max_depth: max_depth).parse
      end
    end

    def initialize(data, max_size:, max_depth:)
      @data = data
      @max_size = max_size
      @max_depth = max_depth
      @pos = 0
      @path = []
    end

    def parse
      if @data.bytesize > @max_size
        raise StrictDecodingError,
              "JSON size #{@data.bytesize} bytes exceeds the limit of #{@max_size} bytes"
      end

      value = parse_value(0)
      skip_whitespace
      raise ParserError, 'Trailing data after JSON document' unless @pos == @data.bytesize

      value
    end

    private

    def current_byte
      @data.getbyte(@pos)
    end

    def skip_whitespace
      @pos += 1 while [0x20, 0x09, 0x0A, 0x0D].include?(current_byte)
    end

    def expect_byte(byte, description)
      raise ParserError, "Expected #{description} at byte #{@pos}" unless current_byte == byte

      @pos += 1
    end

    def check_depth!(depth)
      return unless depth > @max_depth

      raise StrictDecodingError,
            "JSON nesting depth exceeds the limit of #{@max_depth} at #{current_path}"
    end

    def parse_value(depth)
      skip_whitespace
      case current_byte
      when OPEN_BRACE then parse_object(depth + 1)
      when OPEN_BRACKET then parse_array(depth + 1)
      when QUOTE then parse_string
      when 0x74 then parse_literal('true', true)
      when 0x66 then parse_literal('false', false)
      when 0x6E then parse_literal('null', nil)
      else parse_number
      end
    end

    def parse_object(depth)
      check_depth!(depth)
      expect_byte(OPEN_BRACE, "'{'")
      result = {}
      seen = {}
      skip_whitespace
      if current_byte == CLOSE_BRACE
        @pos += 1
        return result
      end

      loop do
        skip_whitespace
        key_offset = @pos
        raise ParserError, "Expected object key at byte #{@pos}" unless current_byte == QUOTE

        key = parse_string
        @path.push(key)
        check_duplicate_key!(seen, key, key_offset)
        seen[key] = key_offset

        skip_whitespace
        expect_byte(COLON, "':'")
        result[key] = parse_value(depth)
        @path.pop

        skip_whitespace
        case current_byte
        when COMMA then @pos += 1
        when CLOSE_BRACE
          @pos += 1
          return result
        else
          raise ParserError, "Expected ',' or '}' at byte #{@pos}"
        end
      end
    end

    def check_duplicate_key!(seen, key, key_offset)
      return unless seen.key?(key)

      raise StrictDecodingError.new(
        "Duplicate key #{key.inspect} at #{current_path}",
        path: current_path,
        key: key,
        first_offset: seen[key],
        second_offset: key_offset
      )
    end

    def parse_array(depth)
      check_depth!(depth)
      expect_byte(OPEN_BRACKET, "'['")
      result = []
      skip_whitespace
      if current_byte == CLOSE_BRACKET
        @pos += 1
        return result
      end

      loop do
        @path.push(result.length)
        result.push(parse_value(depth))
        @path.pop

        skip_whitespace
        case current_byte
        when COMMA then @pos += 1
        when CLOSE_BRACKET
          @pos += 1
          return result
        else
          raise ParserError, "Expected ',' or ']' at byte #{@pos}"
        end
      end
    end

    def parse_string
      expect_byte(QUOTE, "'\"'")
      buffer = String.new(encoding: Encoding::BINARY)
      loop do
        byte = current_byte
        raise ParserError, 'Unterminated string' if byte.nil?

        case byte
        when QUOTE
          @pos += 1
          return finish_string(buffer)
        when BACKSLASH
          @pos += 1
          buffer << parse_escape
        when 0x00..0x1F
          raise ParserError, "Unescaped control character in string at byte #{@pos}"
        else
          buffer << byte
          @pos += 1
        end
      end
    end

    def finish_string(buffer)
      buffer.force_encoding(Encoding::UTF_8)
      raise ParserError, 'Invalid UTF-8 in string' unless buffer.valid_encoding?

      buffer
    end

    def parse_escape
      byte = current_byte
      @pos += 1
      case byte
      when QUOTE then '"'
      when BACKSLASH then '\\'
      when 0x2F then '/'
      when 0x62 then "\b"
      when 0x66 then "\f"
      when 0x6E then "\n"
      when 0x72 then "\r"
      when 0x74 then "\t"
      when 0x75 then parse_unicode_escape
      else
        raise ParserError, "Invalid escape sequence at byte #{@pos - 1}"
      end
    end

    def parse_unicode_escape
      high = read_hex4
      if high.between?(0xD800, 0xDBFF)
        low = read_low_surrogate
        [0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00)].pack('U')
      elsif high.between?(0xDC00, 0xDFFF)
        raise ParserError, 'Unexpected low surrogate in unicode escape'
      else
        [high].pack('U')
      end
    end

    def read_low_surrogate
      unless current_byte == BACKSLASH && @data.getbyte(@pos + 1) == 0x75
        raise ParserError, 'Missing low surrogate in unicode escape'
      end

      @pos += 2
      low = read_hex4
      raise ParserError, 'Invalid low surrogate in unicode escape' unless low.between?(0xDC00, 0xDFFF)

      low
    end

    def read_hex4
      hex = @data.byteslice(@pos, 4)
      if hex.nil? || hex.bytesize < 4 || !hex.match?(/\A[0-9a-fA-F]{4}\z/)
        raise ParserError, "Invalid unicode escape at byte #{@pos}"
      end

      @pos += 4
      hex.to_i(16)
    end

    def parse_literal(word, value)
      raise ParserError, "Invalid literal at byte #{@pos}" unless @data.byteslice(@pos, word.length) == word

      @pos += word.length
      value
    end

    def parse_number
      start = @pos
      @pos += 1 if current_byte == MINUS
      parse_integer_part
      parse_fraction_part
      parse_exponent_part
      text = @data.byteslice(start, @pos - start)
      text.match?(/[.eE]/) ? Float(text) : Integer(text)
    end

    def parse_integer_part
      if current_byte == ZERO
        @pos += 1
      elsif digit_one_to_nine?(current_byte)
        @pos += 1 while digit?(current_byte)
      else
        raise ParserError, "Invalid number at byte #{@pos}"
      end
    end

    def parse_fraction_part
      return unless current_byte == DOT

      @pos += 1
      raise ParserError, "Invalid number at byte #{@pos}" unless digit?(current_byte)

      @pos += 1 while digit?(current_byte)
    end

    def parse_exponent_part
      return unless current_byte == 0x65 || current_byte == 0x45 # e, E

      @pos += 1
      @pos += 1 if current_byte == PLUS || current_byte == MINUS
      raise ParserError, "Invalid number at byte #{@pos}" unless digit?(current_byte)

      @pos += 1 while digit?(current_byte)
    end

    def digit?(byte)
      byte&.between?(0x30, 0x39)
    end

    def digit_one_to_nine?(byte)
      byte&.between?(0x31, 0x39)
    end

    def current_path
      @path.each_with_object(+'$') do |segment, path|
        if segment.is_a?(Integer)
          path << "[#{segment}]"
        elsif segment.match?(/\A[a-zA-Z_][a-zA-Z0-9_]*\z/)
          path << ".#{segment}"
        else
          path << "[#{segment.inspect}]"
        end
      end
    end
  end
end
