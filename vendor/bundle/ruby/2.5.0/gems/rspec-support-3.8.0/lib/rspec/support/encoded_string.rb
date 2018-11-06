module RSpec
  module Support
    # @private
    class EncodedString
      # Reduce allocations by storing constants.
      UTF_8    = "UTF-8"
      US_ASCII = "US-ASCII"
      #
      # In MRI 2.1 'invalid: :replace' changed to also replace an invalid byte sequence
      # see https://github.com/ruby/ruby/blob/v2_1_0/NEWS#L176
      # https://www.ruby-forum.com/topic/6861247
      # https://twitter.com/nalsh/status/553413844685438976
      #
      # For example, given:
      #   "\x80".force_encoding("Emacs-Mule").encode(:invalid => :replace).bytes.to_a
      #
      # On MRI 2.1 or above: 63  # '?'
      # else               : 128 # "\x80"
      #
      # Ruby's default replacement string is:
      #   U+FFFD ("\xEF\xBF\xBD"), for Unicode encoding forms, else
      #   ?      ("\x3F")
      REPLACE = "?"
      ENCODE_UNCONVERTABLE_BYTES =  {
        :invalid => :replace,
        :undef   => :replace,
        :replace => REPLACE
      }
      ENCODE_NO_CONVERTER = {
        :invalid => :replace,
        :replace => REPLACE
      }

      def initialize(string, encoding=nil)
        @encoding = encoding
        @source_encoding = detect_source_encoding(string)
        @string = matching_encoding(string)
      end
      attr_reader :source_encoding

      delegated_methods = String.instance_methods.map(&:to_s) & %w[eql? lines == encoding empty?]
      delegated_methods.each do |name|
        define_method(name) { |*args, &block| @string.__send__(name, *args, &block) }
      end

      def <<(string)
        @string << matching_encoding(string)
      end

      if Ruby.jruby?
        def split(regex_or_string)
          @string.split(matching_encoding(regex_or_string))
        rescue ArgumentError
          # JRuby raises an ArgumentError when splitting a source string that
          # contains invalid bytes.
          remove_invalid_bytes(@string).split regex_or_string
        end
      else
        def split(regex_or_string)
          @string.split(matching_encoding(regex_or_string))
        end
      end

      def to_s
        @string
      end
      alias :to_str :to_s

      if String.method_defined?(:encoding)

        private

        # Encoding Exceptions:
        #
        # Raised by Encoding and String methods:
        #   Encoding::UndefinedConversionError:
        #     when a transcoding operation fails
        #     if the String contains characters invalid for the target encoding
        #     e.g. "\x80".encode('UTF-8','ASCII-8BIT')
        #     vs "\x80".encode('UTF-8','ASCII-8BIT', undef: :replace, replace: '<undef>')
        #     # => '<undef>'
        #   Encoding::CompatibilityError
        #     when Encoding.compatibile?(str1, str2) is nil
        #     e.g. utf_16le_emoji_string.split("\n")
        #     e.g. valid_unicode_string.encode(utf8_encoding) << ascii_string
        #   Encoding::InvalidByteSequenceError:
        #     when the string being transcoded contains a byte invalid for
        #     either the source or target encoding
        #     e.g. "\x80".encode('UTF-8','US-ASCII')
        #     vs "\x80".encode('UTF-8','US-ASCII', invalid: :replace, replace: '<byte>')
        #     # => '<byte>'
        #   ArgumentError
        #     when operating on a string with invalid bytes
        #     e.g."\x80".split("\n")
        #   TypeError
        #     when a symbol is passed as an encoding
        #     Encoding.find(:"UTF-8")
        #     when calling force_encoding on an object
        #     that doesn't respond to #to_str
        #
        # Raised by transcoding methods:
        #   Encoding::ConverterNotFoundError:
        #     when a named encoding does not correspond with a known converter
        #     e.g. 'abc'.force_encoding('UTF-8').encode('foo')
        #     or a converter path cannot be found
        #     e.g. "\x80".force_encoding('ASCII-8BIT').encode('Emacs-Mule')
        #
        # Raised by byte <-> char conversions
        #   RangeError: out of char range
        #     e.g. the UTF-16LE emoji: 128169.chr
        def matching_encoding(string)
          string = remove_invalid_bytes(string)
          string.encode(@encoding)
        rescue Encoding::UndefinedConversionError, Encoding::InvalidByteSequenceError
          string.encode(@encoding, ENCODE_UNCONVERTABLE_BYTES)
        rescue Encoding::ConverterNotFoundError
          string.dup.force_encoding(@encoding).encode(ENCODE_NO_CONVERTER)
        end

        # Prevents raising ArgumentError
        if String.method_defined?(:scrub)
          # https://github.com/ruby/ruby/blob/eeb05e8c11/doc/NEWS-2.1.0#L120-L123
          # https://github.com/ruby/ruby/blob/v2_1_0/string.c#L8242
          # https://github.com/hsbt/string-scrub
          # https://github.com/rubinius/rubinius/blob/v2.5.2/kernel/common/string.rb#L1913-L1972
          def remove_invalid_bytes(string)
            string.scrub(REPLACE)
          end
        else
          # http://stackoverflow.com/a/8711118/879854
          # Loop over chars in a string replacing chars
          # with invalid encoding, which is a pretty good proxy
          # for the invalid byte sequence that causes an ArgumentError
          def remove_invalid_bytes(string)
            string.chars.map do |char|
              char.valid_encoding? ? char : REPLACE
            end.join
          end
        end

        def detect_source_encoding(string)
          string.encoding
        end

        def self.pick_encoding(source_a, source_b)
          Encoding.compatible?(source_a, source_b) || Encoding.default_external
        end
      else

        def self.pick_encoding(_source_a, _source_b)
        end

        private

        def matching_encoding(string)
          string
        end

        def detect_source_encoding(_string)
          US_ASCII
        end
      end
    end
  end
end
