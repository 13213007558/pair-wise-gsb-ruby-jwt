# frozen_string_literal: true

RSpec.describe JWT::JSON do
  describe '.parse in strict mode' do
    def parse_strict(document, **options)
      described_class.parse(document, strict: true, **options)
    end

    context 'with well formed documents' do
      [
        '{}',
        '[]',
        'null',
        'true',
        'false',
        '0',
        '-1',
        '1.5',
        '1E10',
        '-0.25e-3',
        '"a string"',
        '{"iss":"a","nested":{"x":[1,true,false,null,{}]}}',
        '{"a":"he said \" {}{ \\\\ 中😀"}',
        '{"iss":"iss"}'
      ].each do |document|
        it "parses #{document.inspect} identically to the standard library parser" do
          expect(parse_strict(document)).to eq(::JSON.parse(document))
        end
      end

      it 'accepts documents nested up to the configured depth' do
        document = '[' * 99 + '1' + ']' * 99
        expect(parse_strict(document)).to eq(::JSON.parse(document))
      end
    end

    context 'with duplicate members' do
      def expect_duplicate(document, path:, &block)
        parse_strict(document)
        raise 'expected a DuplicateJSONKeyError'
      rescue JWT::DuplicateJSONKeyError => e
        raw = document.b
        aggregate_failures do
          expect(e.path).to eq(path)
          expect(e).to be_a(JWT::JSONParseError)
          expect(e).to be_a(JWT::MalformedTokenError)
          expect(raw.getbyte(e.first_position)).to eq(0x22)
          expect(raw.getbyte(e.duplicate_position)).to eq(0x22)
          expect(e.duplicate_position).to be > e.first_position
          expect(e.position).to eq(e.duplicate_position)
          block&.call(e)
        end
      end

      it 'reports the path and byte positions of both keys at the top level' do
        document = '{"iss":"a","iss":"b"}'
        expect_duplicate(document, path: '$.iss') do |e|
          expect(e.key).to eq('iss')
          expect(e.first_position).to eq(1)
          expect(e.duplicate_position).to eq(11)
          expect(e.message).to include('$.iss', 'byte positions 1 and 11')
        end
      end

      it 'reports the path relative to the nested object' do
        expect_duplicate('{"x":{"iss":1,"iss":2}}', path: '$.x.iss') do |e|
          expect(e.first_position).to eq(6)
          expect(e.duplicate_position).to eq(14)
        end
      end

      it 'reports array indices in the JSON path' do
        expect_duplicate('{"a":[{"x":1},{"iss":1,"iss":2}]}', path: '$.a[1].iss')
      end

      it 'quotes member names that are not simple identifiers' do
        expect_duplicate('{"key space":1,"key space":2}', path: '$["key space"]')
        expect_duplicate('{"weird[":1,"weird[":2}', path: '$["weird["]')
        expect_duplicate('{"😀":1,"😀":2}', path: '$["😀"]')
      end

      it 'treats a literal key and the same key written as a Unicode escape as duplicates' do
        document = '{"iss":1,"\u0069ss":2}'
        expect_duplicate(document, path: '$.iss') do |e|
          expect(e.key).to eq('iss')
        end
      end

      it 'does not treat escapes that unescape to different names as duplicates' do
        document = '{"iss":1,"\u0069SS":0}'
        expect(parse_strict(document)).to eq('iss' => 1, 'iSS' => 0)
      end

      it 'treats surrogate pair escapes and the equivalent UTF-8 key as duplicates' do
        document = '{"\uD83D\uDE00":1,"😀":2}'
        expect_duplicate(document, path: '$["😀"]') do |e|
          expect(e.key).to eq('😀')
        end
      end

      it 'is not confused by braces and quotes inside string values' do
        # A fake escaped "iss" lives inside the string value of "a"; only the real top-level
        # occurrence together with the closing duplicate is a duplicate member.
        sneaky_value = '{"iss": 1, "x":'
        document = '{"a":' + sneaky_value.to_json + ',"iss":1,"iss":2}'
        expect_duplicate(document, path: '$.iss')
      end

      it 'keeps reporting the correct path after a parse error inside an earlier member' do
        expect_duplicate('{"a":[1,{"x":1,"x":2}],"b":3}', path: '$.a[1].x')
      end
    end

    context 'with malformed documents' do
      [
        '',
        '{',
        '}',
        '{,}',
        '{"a" 1}',
        '[1,]',
        '{"a":1,}',
        'tru',
        'nulx',
        '1.',
        '[1 2]',
        '{}x',
        '{"a": 1.}',
        '{"a":--1}',
        '-',
        '{"a":tru e}',
        '{"a":"\\x"}',
        '{"a":"\\u12"}',
        '{"a":"\\ud800x"}',
        '{"a":"\\udc00"}',
        '{"a":"\\uD800\\uDC00"',
        '{"a":01}',
        '{"a":-01}'
      ].each do |document|
        it "rejects #{document.inspect}" do
          expect { parse_strict(document) }.to raise_error(JWT::JSONParseError) do |e|
            expect(e).to be_a(JWT::MalformedTokenError)
            expect(e.position).to be_a(Integer)
          end
        end
      end

      it 'rejects unescaped control characters inside strings' do
        expect { parse_strict("{\"a\":\"\x01\"}") }
          .to raise_error(JWT::JSONParseError, /control character/)
      end

      it 'rejects invalid UTF-8 byte sequences' do
        expect { parse_strict("{\"a\":\"\xC0\xAF\"".b) }
          .to raise_error(JWT::JSONParseError, /UTF-8/i)
        expect { parse_strict("{\"a\":\"\xED\xA0\x80\"".b) }
          .to raise_error(JWT::JSONParseError, /UTF-8/i)
        expect { parse_strict("{\"a\":\"\xE4\xB8\"".b) }
          .to raise_error(JWT::JSONParseError)
      end
    end

    context 'with the size and depth limits' do
      it 'rejects documents larger than the configured size' do
        expect { parse_strict('{} ', max_size: 1) }
          .to raise_error(JWT::JSONParseError, /exceeds the maximum size of 1 bytes/)
      end

      it 'rejects documents nested deeper than the configured depth' do
        document = '[' * 100 + '1' + ']' * 100
        expect { parse_strict(document) }
          .to raise_error(JWT::JSONParseError, /nesting depth exceeds the maximum of 100/)
      end

      it 'applies the depth limit to nested objects as well' do
        document = '{"a":' * 100 + '1' + '}' * 100
        expect { parse_strict(document) }
          .to raise_error(JWT::JSONParseError, /nesting depth/)
      end
    end

    context 'with a frozen input string' do
      it 'does not mutate its argument' do
        document = '{"iss":"a"}'.freeze
        expect(parse_strict(document)).to eq('iss' => 'a')
      end
    end
  end

  describe '.parse in default mode' do
    it 'behaves as before and keeps the last value of duplicate members' do
      expect(described_class.parse('{"iss":"a","iss":"b"}')).to eq('iss' => 'b')
    end

    it 'raises ::JSON::ParserError for malformed documents' do
      expect { described_class.parse('{') }.to raise_error(::JSON::ParserError)
    end
  end

  describe '.generate' do
    it 'serializes data' do
      expect(described_class.generate('a' => 1)).to eq('{"a":1}')
    end
  end
end
