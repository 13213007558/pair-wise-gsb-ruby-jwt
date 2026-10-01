# frozen_string_literal: true

RSpec.describe JWT::StrictJSON do
  describe '.parse' do
    it 'parses a regular JSON document' do
      expect(described_class.parse('{"a":1,"b":{"c":[1,2.5,"x",true,false,null]}}')).to eq(
        'a' => 1, 'b' => { 'c' => [1, 2.5, 'x', true, false, nil] }
      )
    end

    it 'is not confused by braces and quotes inside strings' do
      expect(described_class.parse('{"a":"}{\\"","b":2}')).to eq('a' => '}{"', 'b' => 2)
    end

    it 'decodes unicode escapes in keys' do
      expect(described_class.parse('{"\\u0069ss":1}')).to eq('iss' => 1)
    end

    it 'decodes surrogate pairs in keys' do
      expect(described_class.parse('{"😀":1}')).to eq('😀' => 1)
    end

    context 'with duplicate keys' do
      it 'rejects duplicates at the top level' do
        expect { described_class.parse('{"iss":"a","iss":"b"}') }
          .to raise_error(JWT::StrictDecodingError, 'Duplicate key "iss" at $.iss')
      end

      it 'reports the byte offsets of both key occurrences' do
        error = nil
        begin
          described_class.parse('{"iss":"a","iss":"b"}')
        rescue JWT::StrictDecodingError => e
          error = e
        end
        expect(error.path).to eq('$.iss')
        expect(error.key).to eq('iss')
        expect(error.first_offset).to eq(1)
        expect(error.second_offset).to eq(11)
      end

      it 'rejects duplicates nested in objects' do
        expect { described_class.parse('{"a":{"x":1,"x":2}}') }
          .to raise_error(JWT::StrictDecodingError, 'Duplicate key "x" at $.a.x')
      end

      it 'rejects duplicates nested in arrays' do
        expect { described_class.parse('{"a":[{"x":1,"x":2}]}') }
          .to raise_error(JWT::StrictDecodingError, 'Duplicate key "x" at $.a[0].x')
      end

      it 'treats a unicode-escaped key as a duplicate of the literal key' do
        expect { described_class.parse('{"iss":"a","\\u0069ss":"b"}') }
          .to raise_error(JWT::StrictDecodingError, 'Duplicate key "iss" at $.iss')
      end

      it 'does not treat keys with different decoded values as duplicates' do
        expect(described_class.parse('{"\\u0069ss":1,"iss2":2}')).to eq('iss' => 1, 'iss2' => 2)
      end

      it 'reports the error as a JWT::MalformedTokenError descendant' do
        expect { described_class.parse('{"a":1,"a":2}') }.to raise_error(JWT::MalformedTokenError)
      end
    end

    context 'with limits' do
      it 'rejects documents exceeding the size limit' do
        expect { described_class.parse('{"a":1}', max_size: 3) }
          .to raise_error(JWT::StrictDecodingError, /exceeds the limit of 3 bytes/)
      end

      it 'rejects documents exceeding the depth limit' do
        expect { described_class.parse('[[[[1]]]]', max_depth: 3) }
          .to raise_error(JWT::StrictDecodingError, /nesting depth exceeds the limit of 3/)
      end

      it 'accepts documents within the depth limit' do
        expect(described_class.parse('[[[1]]]', max_depth: 3)).to eq([[[1]]])
      end
    end

    context 'with malformed JSON' do
      it 'raises ParserError for trailing data' do
        expect { described_class.parse('{"a":1} x') }.to raise_error(JWT::StrictJSON::ParserError)
      end

      it 'raises ParserError for unterminated strings' do
        expect { described_class.parse('{"a":"x}') }.to raise_error(JWT::StrictJSON::ParserError)
      end

      it 'raises ParserError for invalid escapes' do
        expect { described_class.parse('{"a":"\\q"}') }.to raise_error(JWT::StrictJSON::ParserError)
      end

      it 'raises ParserError for lone surrogates' do
        expect { described_class.parse('{"a":"\\ud800x"}') }.to raise_error(JWT::StrictJSON::ParserError)
      end

      it 'raises ParserError for invalid numbers' do
        expect { described_class.parse('{"a":01}') }.to raise_error(JWT::StrictJSON::ParserError)
      end

      it 'raises ParserError for unescaped control characters' do
        expect { described_class.parse("{\"a\":\"x\ty\"}") }.to raise_error(JWT::StrictJSON::ParserError)
      end
    end
  end
end
