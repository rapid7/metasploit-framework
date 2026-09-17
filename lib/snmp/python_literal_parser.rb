# frozen_string_literal: true

module SNMP
  # Parses the primitive Python literal subset emitted by `smidump -f python`.
  class PythonLiteralParser
    MAX_DEPTH = 64

    class ParseError < StandardError; end

    # @param source [String] Python literal source
    # @param offset [Integer] offset at which the literal starts
    def initialize(source, offset: 0)
      @source = source
      @offset = offset
    end

    # @return [Hash] parsed MIB dictionary
    # @raise [ParseError] if source contains anything except primitive literals
    def parse
      value = parse_value(0)
      skip_ignored
      raise ParseError, 'Unexpected content after MIB data' unless eof?
      raise ParseError, 'MIB data must be a dictionary' unless value.is_a?(Hash)

      value
    end

    private

    def parse_value(depth)
      raise ParseError, 'MIB data is nested too deeply' if depth > MAX_DEPTH

      skip_ignored
      case current
      when '{' then parse_hash(depth + 1)
      when '[', '(' then parse_sequence(depth + 1)
      when "'", '"' then parse_string
      when '-', '0'..'9' then parse_integer
      else parse_keyword
      end
    end

    def parse_hash(depth)
      consume('{')
      result = {}
      skip_ignored
      return consume('}') && result if current == '}'

      loop do
        key = parse_value(depth)
        raise ParseError, 'MIB dictionary keys must be strings' unless key.is_a?(String)

        skip_ignored
        consume(':')
        result[key] = parse_value(depth)
        skip_ignored
        break if current == '}'

        consume(',')
        skip_ignored
        break if current == '}'
      end
      consume('}')
      result
    end

    def parse_sequence(depth)
      closer = current == '[' ? ']' : ')'
      @offset += 1
      result = []
      skip_ignored
      return consume(closer) && result if current == closer

      loop do
        result << parse_value(depth)
        skip_ignored
        break if current == closer

        consume(',')
        skip_ignored
        break if current == closer
      end
      consume(closer)
      result
    end

    def parse_string
      quote = current
      consume(quote)
      result = String.new
      until eof?
        char = take
        return result if char == quote

        unless char == '\\'
          result << char
          next
        end

        raise ParseError, 'Unterminated escape sequence' if eof?

        result << unescape(take)
      end
      raise ParseError, 'Unterminated string'
    end

    def unescape(escaped)
      return escaped if ['\\', "'", '"'].include?(escaped)
      return [read_digits(2, 16, '\\x')].pack('U') if escaped == 'x'
      return [read_digits(4, 16, '\\u')].pack('U') if escaped == 'u'
      return [read_octal(escaped)].pack('U') if escaped.match?(/[0-7]/)

      replacements = { 'n' => "\n", 'r' => "\r", 't' => "\t", 'b' => "\b", 'f' => "\f", 'v' => "\v", 'a' => "\a" }
      replacements.fetch(escaped) { raise ParseError, "Unsupported escape sequence \\#{escaped}" }
    end

    def read_digits(length, base, prefix)
      digits = @source[@offset, length]
      unless digits&.length == length && digits.match?(base == 16 ? /\A[0-9A-Fa-f]+\z/ : /\A[0-7]+\z/)
        raise ParseError, "Invalid #{prefix} escape sequence"
      end

      @offset += length
      digits.to_i(base)
    end

    def read_octal(first_digit)
      digits = first_digit
      2.times do
        break unless current&.match?(/[0-7]/)

        digits << take
      end
      digits.to_i(8)
    end

    def parse_integer
      token = @source[@offset..].match(/\A-?\d+/)&.[](0)
      raise ParseError, 'Invalid integer' unless token

      @offset += token.length
      Integer(token, 10)
    end

    def parse_keyword
      token = @source[@offset..].match(/\A[A-Za-z_][A-Za-z0-9_]*/)&.[](0)
      @offset += token.length if token
      return nil if token == 'None'
      return true if token == 'True'
      return false if token == 'False'

      raise ParseError, "Unsupported MIB expression #{token.inspect}"
    end

    def skip_ignored
      loop do
        @offset += 1 while !eof? && @source[@offset].match?(/\s/)
        break unless current == '#'

        @offset += 1 until eof? || current == "\n"
      end
    end

    def consume(expected)
      raise ParseError, "Expected #{expected.inspect}" unless current == expected

      @offset += 1
      true
    end

    def take
      char = current
      @offset += 1
      char
    end

    def current
      @source[@offset]
    end

    def eof?
      @offset >= @source.length
    end
  end
end
