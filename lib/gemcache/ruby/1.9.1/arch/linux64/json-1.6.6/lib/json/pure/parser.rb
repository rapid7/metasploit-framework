require 'strscan'

module JSON
  module Pure
    # This class implements the JSON parser that is used to parse a JSON string
    # into a Ruby data structure.
    class Parser < StringScanner
      STRING                = /" ((?:[^\x0-\x1f"\\] |
                                   # escaped special characters:
                                  \\["\\\/bfnrt] |
                                  \\u[0-9a-fA-F]{4} |
                                   # match all but escaped special characters:
                                  \\[\x20-\x21\x23-\x2e\x30-\x5b\x5d-\x61\x63-\x65\x67-\x6d\x6f-\x71\x73\x75-\xff])*)
                              "/nx
      INTEGER               = /(-?0|-?[1-9]\d*)/
      FLOAT                 = /(-?
                                (?:0|[1-9]\d*)
                                (?:
                                  \.\d+(?i:e[+-]?\d+) |
                                  \.\d+ |
                                  (?i:e[+-]?\d+)
                                )
                                )/x
      NAN                   = /NaN/
      INFINITY              = /Infinity/
      MINUS_INFINITY        = /-Infinity/
      OBJECT_OPEN           = /\{/
      OBJECT_CLOSE          = /\}/
      ARRAY_OPEN            = /\[/
      ARRAY_CLOSE           = /\]/
      PAIR_DELIMITER        = /:/
      COLLECTION_DELIMITER  = /,/
      TRUE                  = /true/
      FALSE                 = /false/
      NULL                  = /null/
      IGNORE                = %r(
        (?:
         //[^\n\r]*[\n\r]| # line comments
         /\*               # c-style comments
         (?:
          [^*/]|        # normal chars
          /[^*]|        # slashes that do not start a nested comment
          \*[^/]|       # asterisks that do not end this comment
          /(?=\*/)      # single slash before this comment's end
         )*
           \*/               # the End of this comment
           |[ \t\r\n]+       # whitespaces: space, horicontal tab, lf, cr
        )+
      )mx

      UNPARSED = Object.new

      # Creates a new JSON::Pure::Parser instance for the string _source_.
      #
      # It will be configured by the _opts_ hash. _opts_ can have the following
      # keys:
      # * *max_nesting*: The maximum depth of nesting allowed in the parsed data
      #   structures. Disable depth checking with :max_nesting => false|nil|0,
      #   it defaults to 19.
      # * *allow_nan*: If set to true, allow NaN, Infinity and -Infinity in
      #   defiance of RFC 4627 to be parsed by the Parser. This option defaults
      #   to false.
      # * *symbolize_names*: If set to true, returns symbols for the names
      #   (keys) in a JSON object. Otherwise strings are returned, which is also
      #   the default.
      # * *create_additions*: If set to false, the Parser doesn't create
      #   additions even if a matchin class and create_id was found. This option
      #   defaults to true.
      # * *object_class*: Defaults to Hash
      # * *array_class*: Defaults to Array
      # * *quirks_mode*: Enables quirks_mode for parser, that is for example
      #   parsing single JSON values instead of documents is possible.
      def initialize(source, opts = {})
        opts ||= {}
        unless @quirks_mode = opts[:quirks_mode]
          source = convert_encoding source
        end
        super source
        if !opts.key?(:max_nesting) # defaults to 19
          @max_nesting = 19
        elsif opts[:max_nesting]
          @max_nesting = opts[:max_nesting]
        else
          @max_nesting = 0
        end
        @allow_nan = !!opts[:allow_nan]
        @symbolize_names = !!opts[:symbolize_names]
        if opts.key?(:create_additions)
          @create_additions = !!opts[:create_additions]
        else
          @create_additions = true
        end
        @create_id = @create_additions ? JSON.create_id : nil
        @object_class = opts[:object_class] || Hash
        @array_class  = opts[:array_class] || Array
        @match_string = opts[:match_string]
      end

      alias source string

      def quirks_mode?
        !!@quirks_mode
      end

      def reset
        super
        @current_nesting = 0
      end

      # Parses the current JSON string _source_ and returns the complete data
      # structure as a result.
      def parse
        reset
        obj = nil
        if @quirks_mode
          while !eos? && skip(IGNORE)
          end
          if eos?
            raise ParserError, "source did not contain any JSON!"
          else
            obj = parse_value
            obj == UNPARSED and raise ParserError, "source did not contain any JSON!"
          end
        else
          until eos?
            case
            when scan(OBJECT_OPEN)
              obj and raise ParserError, "source '#{peek(20)}' not in JSON!"
              @current_nesting = 1
              obj = parse_object
            when scan(ARRAY_OPEN)
              obj and raise ParserError, "source '#{peek(20)}' not in JSON!"
              @current_nesting = 1
              obj = parse_array
            when skip(IGNORE)
              ;
            else
              raise ParserError, "source '#{peek(20)}' not in JSON!"
            end
          end
          obj or raise ParserError, "source did not contain any JSON!"
        end
        obj
      end

      private

      def convert_encoding(source)
        if source.respond_to?(:to_str)
          source = source.to_str
        else
          raise TypeError, "#{source.inspect} is not like a string"
        end
        if defined?(::Encoding)
          if source.encoding == ::Encoding::ASCII_8BIT
            b = source[0, 4].bytes.to_a
            source =
              case
              when b.size >= 4 && b[0] == 0 && b[1] == 0 && b[2] == 0
                source.dup.force_encoding(::Encoding::UTF_32BE).encode!(::Encoding::UTF_8)
              when b.size >= 4 && b[0] == 0 && b[2] == 0
                source.dup.force_encoding(::Encoding::UTF_16BE).encode!(::Encoding::UTF_8)
              when b.size >= 4 && b[1] == 0 && b[2] == 0 && b[3] == 0
                source.dup.force_encoding(::Encoding::UTF_32LE).encode!(::Encoding::UTF_8)
              when b.size >= 4 && b[1] == 0 && b[3] == 0
                source.dup.force_encoding(::Encoding::UTF_16LE).encode!(::Encoding::UTF_8)
              else
                source.dup
              end
          else
            source = source.encode(::Encoding::UTF_8)
          end
          source.force_encoding(::Encoding::ASCII_8BIT)
        else
          b = source
          source =
            case
            when b.size >= 4 && b[0] == 0 && b[1] == 0 && b[2] == 0
              JSON.iconv('utf-8', 'utf-32be', b)
            when b.size >= 4 && b[0] == 0 && b[2] == 0
              JSON.iconv('utf-8', 'utf-16be', b)
            when b.size >= 4 && b[1] == 0 && b[2] == 0 && b[3] == 0
              JSON.iconv('utf-8', 'utf-32le', b)
            when b.size >= 4 && b[1] == 0 && b[3] == 0
              JSON.iconv('utf-8', 'utf-16le', b)
            else
              b
            end
        end
        source
      end

      # Unescape characters in strings.
      UNESCAPE_MAP = Hash.new { |h, k| h[k] = k.chr }
      UNESCAPE_MAP.update({
        ?"  => '"',
        ?\\ => '\\',
        ?/  => '/',
        ?b  => "\b",
        ?f  => "\f",
        ?n  => "\n",
        ?r  => "\r",
        ?t  => "\t",
        ?u  => nil,
      })

      EMPTY_8BIT_STRING = ''
      if ::String.method_defined?(:encode)
        EMPTY_8BIT_STRING.force_encoding Encoding::ASCII_8BIT
      end

      def parse_string
        if scan(STRING)
          return '' if self[1].empty?
          string = self[1].gsub(%r((?:\\[\\bfnrt"/]|(?:\\u(?:[A-Fa-f\d]{4}))+|\\[\x20-\xff]))n) do |c|
            if u = UNESCAPE_MAP[$&[1]]
              u
            else # \uXXXX
              bytes = EMPTY_8BIT_STRING.dup
              i = 0
              while c[6 * i] == ?\\ && c[6 * i + 1] == ?u
                bytes << c[6 * i + 2, 2].to_i(16) << c[6 * i + 4, 2].to_i(16)
                i += 1
              end
              JSON.iconv('utf-8', 'utf-16be', bytes)
            end
          end
          if string.respond_to?(:force_encoding)
            string.force_encoding(::Encoding::UTF_8)
          end
          if @create_additions and @match_string
            for (regexp, klass) in @match_string
              klass.json_creatable? or next
              string =~ regexp and return klass.json_create(string)
            end
          end
          string
        else
          UNPARSED
        end
      rescue => e
        raise ParserError, "Caught #{e.class} at '#{peek(20)}': #{e}"
      end

      def parse_value
        case
        when scan(FLOAT)
          Float(self[1])
        when scan(INTEGER)
          Integer(self[1])
        when scan(TRUE)
          true
        when scan(FALSE)
          false
        when scan(NULL)
          nil
        when (string = parse_string) != UNPARSED
          string
        when scan(ARRAY_OPEN)
          @current_nesting += 1
          ary = parse_array
          @current_nesting -= 1
          ary
        when scan(OBJECT_OPEN)
          @current_nesting += 1
          obj = parse_object
          @current_nesting -= 1
          obj
        when @allow_nan && scan(NAN)
          NaN
        when @allow_nan && scan(INFINITY)
          Infinity
        when @allow_nan && scan(MINUS_INFINITY)
          MinusInfinity
        else
          UNPARSED
        end
      end

      def parse_array
        raise NestingError, "nesting of #@current_nesting is too deep" if
          @max_nesting.nonzero? && @current_nesting > @max_nesting
        result = @array_class.new
        delim = false
        until eos?
          case
          when (value = parse_value) != UNPARSED
            delim = false
            result << value
            skip(IGNORE)
            if scan(COLLECTION_DELIMITER)
              delim = true
            elsif match?(ARRAY_CLOSE)
              ;
            else
              raise ParserError, "expected ',' or ']' in array at '#{peek(20)}'!"
            end
          when scan(ARRAY_CLOSE)
            if delim
              raise ParserError, "expected next element in array at '#{peek(20)}'!"
            end
            break
          when skip(IGNORE)
            ;
          else
            raise ParserError, "unexpected token in array at '#{peek(20)}'!"
          end
        end
        result
      end

      def parse_object
        raise NestingError, "nesting of #@current_nesting is too deep" if
          @max_nesting.nonzero? && @current_nesting > @max_nesting
        result = @object_class.new
        delim = false
        until eos?
          case
          when (string = parse_string) != UNPARSED
            skip(IGNORE)
            unless scan(PAIR_DELIMITER)
              raise ParserError, "expected ':' in object at '#{peek(20)}'!"
            end
            skip(IGNORE)
            unless (value = parse_value).equal? UNPARSED
              result[@symbolize_names ? string.to_sym : string] = value
              delim = false
              skip(IGNORE)
              if scan(COLLECTION_DELIMITER)
                delim = true
              elsif match?(OBJECT_CLOSE)
                ;
              else
                raise ParserError, "expected ',' or '}' in object at '#{peek(20)}'!"
              end
            else
              raise ParserError, "expected value in object at '#{peek(20)}'!"
            end
          when scan(OBJECT_CLOSE)
            if delim
              raise ParserError, "expected next name, value pair in object at '#{peek(20)}'!"
            end
            if @create_additions and klassname = result[@create_id]
              klass = JSON.deep_const_get klassname
              break unless klass and klass.json_creatable?
              result = klass.json_create(result)
            end
            break
          when skip(IGNORE)
            ;
          else
            raise ParserError, "unexpected token in object at '#{peek(20)}'!"
          end
        end
        result
      end
    end
  end
end
