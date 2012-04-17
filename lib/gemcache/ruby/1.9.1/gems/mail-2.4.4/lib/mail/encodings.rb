# encoding: utf-8

module Mail
  # Raised when attempting to decode an unknown encoding type
  class UnknownEncodingType < StandardError #:nodoc:
  end

  module Encodings

    include Mail::Patterns
    extend  Mail::Utilities

    @transfer_encodings = {}

    # Register transfer encoding
    #
    # Example
    #
    # Encodings.register "base64", Mail::Encodings::Base64
    def Encodings.register(name, cls)
        @transfer_encodings[get_name(name)] = cls
    end

    # Is the encoding we want defined?
    #
    # Example:
    #
    #  Encodings.defined?(:base64) #=> true
    def Encodings.defined?( str )
      @transfer_encodings.include? get_name(str)
    end

    # Gets a defined encoding type, QuotedPrintable or Base64 for now.
    #
    # Each encoding needs to be defined as a Mail::Encodings::ClassName for
    # this to work, allows us to add other encodings in the future.
    #
    # Example:
    #
    #  Encodings.get_encoding(:base64) #=> Mail::Encodings::Base64
    def Encodings.get_encoding( str )
      @transfer_encodings[get_name(str)]
    end

    def Encodings.get_all
      @transfer_encodings.values
    end

    def Encodings.get_name(enc)
      enc = enc.to_s.gsub("-", "_").downcase
    end

    # Encodes a parameter value using URI Escaping, note the language field 'en' can
    # be set using Mail::Configuration, like so:
    #
    #  Mail.defaults.do
    #    param_encode_language 'jp'
    #  end
    #
    # The character set used for encoding will either be the value of $KCODE for
    # Ruby < 1.9 or the encoding on the string passed in.
    #
    # Example:
    #
    #  Mail::Encodings.param_encode("This is fun") #=> "us-ascii'en'This%20is%20fun"
    def Encodings.param_encode(str)
      case
      when str.ascii_only? && str =~ TOKEN_UNSAFE
        %Q{"#{str}"}
      when str.ascii_only?
        str
      else
        RubyVer.param_encode(str)
      end
    end

    # Decodes a parameter value using URI Escaping.
    #
    # Example:
    #
    #  Mail::Encodings.param_decode("This%20is%20fun", 'us-ascii') #=> "This is fun"
    #
    #  str = Mail::Encodings.param_decode("This%20is%20fun", 'iso-8559-1')
    #  str.encoding #=> 'ISO-8859-1'      ## Only on Ruby 1.9
    #  str #=> "This is fun"
    def Encodings.param_decode(str, encoding)
      RubyVer.param_decode(str, encoding)
    end

    # Decodes or encodes a string as needed for either Base64 or QP encoding types in
    # the =?<encoding>?[QB]?<string>?=" format.
    #
    # The output type needs to be :decode to decode the input string or :encode to
    # encode the input string.  The character set used for encoding will either be
    # the value of $KCODE for Ruby < 1.9 or the encoding on the string passed in.
    #
    # On encoding, will only send out Base64 encoded strings.
    def Encodings.decode_encode(str, output_type)
      case
      when output_type == :decode
        Encodings.value_decode(str)
      else
        if str.ascii_only?
          str
        else
          Encodings.b_value_encode(str, find_encoding(str))
        end
      end
    end

    # Decodes a given string as Base64 or Quoted Printable, depending on what
    # type it is.
    #
    # String has to be of the format =?<encoding>?[QB]?<string>?=
    def Encodings.value_decode(str)
      # Optimization: If there's no encoded-words in the string, just return it
      return str unless str.index("=?")

      str = str.gsub(/\?=(\s*)=\?/, '?==?') # Remove whitespaces between 'encoded-word's

      # Split on white-space boundaries with capture, so we capture the white-space as well
      str.split(/([ \t])/).map do |text|
        if text.index('=?') .nil?
          text
        else
          # Join QP encoded-words that are adjacent to avoid decoding partial chars
          text.gsub!(/\?\=\=\?.+?\?[Qq]\?/m, '') if text =~ /\?==\?/

          # Search for occurences of quoted strings or plain strings
          text.scan(/(                                  # Group around entire regex to include it in matches
                       \=\?[^?]+\?([QB])\?[^?]+?\?\=  # Quoted String with subgroup for encoding method
                       |                                # or
                       .+?(?=\=\?|$)                    # Plain String
                     )/xmi).map do |matches|
            string, method = *matches
            if    method == 'b' || method == 'B'
              b_value_decode(string)
            elsif method == 'q' || method == 'Q'
              q_value_decode(string)
            else
              string
            end
          end
        end
      end.join("")
    end

    # Takes an encoded string of the format =?<encoding>?[QB]?<string>?=
    def Encodings.unquote_and_convert_to(str, to_encoding)
      original_encoding = split_encoding_from_string( str )

      output = value_decode( str ).to_s

      if original_encoding.to_s.downcase.gsub("-", "") == to_encoding.to_s.downcase.gsub("-", "")
        output
      elsif original_encoding && to_encoding
        begin
          if RUBY_VERSION >= '1.9'
            output.encode(to_encoding)
          else
            require 'iconv'
            Iconv.iconv(to_encoding, original_encoding, output).first
          end
        rescue Iconv::IllegalSequence, Iconv::InvalidEncoding, Errno::EINVAL
          # the 'from' parameter specifies a charset other than what the text
          # actually is...not much we can do in this case but just return the
          # unconverted text.
          #
          # Ditto if either parameter represents an unknown charset, like
          # X-UNKNOWN.
          output
        end
      else
        output
      end
    end

    def Encodings.address_encode(address, charset = 'utf-8')
      if address.is_a?(Array)
        # loop back through for each element
        address.map { |a| Encodings.address_encode(a, charset) }.join(", ")
      else
        # find any word boundary that is not ascii and encode it
        encode_non_usascii(address, charset)
      end
    end

    def Encodings.encode_non_usascii(address, charset)
      return address if address.ascii_only? or charset.nil?
      us_ascii = %Q{\x00-\x7f}
      # Encode any non usascii strings embedded inside of quotes
      address.gsub!(/(".*?[^#{us_ascii}].*?")/) { |s| Encodings.b_value_encode(unquote(s), charset) }
      # Then loop through all remaining items and encode as needed
      tokens = address.split(/\s/)
      map_with_index(tokens) do |word, i|
        if word.ascii_only?
          word
        else
          previous_non_ascii = tokens[i-1] && !tokens[i-1].ascii_only?
          if previous_non_ascii
            word = " #{word}"
          end
          Encodings.b_value_encode(word, charset)
        end
      end.join(' ')
    end

    # Encode a string with Base64 Encoding and returns it ready to be inserted
    # as a value for a field, that is, in the =?<charset>?B?<string>?= format
    #
    # Example:
    #
    #  Encodings.b_value_encode('This is あ string', 'UTF-8')
    #  #=> "=?UTF-8?B?VGhpcyBpcyDjgYIgc3RyaW5n?="
    def Encodings.b_value_encode(encoded_str, encoding = nil)
      return encoded_str if encoded_str.to_s.ascii_only?
      string, encoding = RubyVer.b_value_encode(encoded_str, encoding)
      map_lines(string) do |str|
        "=?#{encoding}?B?#{str.chomp}?="
      end.join(" ")
    end

    # Encode a string with Quoted-Printable Encoding and returns it ready to be inserted
    # as a value for a field, that is, in the =?<charset>?Q?<string>?= format
    #
    # Example:
    #
    #  Encodings.q_value_encode('This is あ string', 'UTF-8')
    #  #=> "=?UTF-8?Q?This_is_=E3=81=82_string?="
    def Encodings.q_value_encode(encoded_str, encoding = nil)
      return encoded_str if encoded_str.to_s.ascii_only?
      string, encoding = RubyVer.q_value_encode(encoded_str, encoding)
      string.gsub!("=\r\n", '') # We already have limited the string to the length we want
      map_lines(string) do |str|
        "=?#{encoding}?Q?#{str.chomp.gsub(/ /, '_')}?="
      end.join(" ")
    end

    private

    # Decodes a Base64 string from the "=?UTF-8?B?VGhpcyBpcyDjgYIgc3RyaW5n?=" format
    #
    # Example:
    #
    #  Encodings.b_value_decode("=?UTF-8?B?VGhpcyBpcyDjgYIgc3RyaW5n?=")
    #  #=> 'This is あ string'
    def Encodings.b_value_decode(str)
      RubyVer.b_value_decode(str)
    end

    # Decodes a Quoted-Printable string from the "=?UTF-8?Q?This_is_=E3=81=82_string?=" format
    #
    # Example:
    #
    #  Encodings.q_value_decode("=?UTF-8?Q?This_is_=E3=81=82_string?=")
    #  #=> 'This is あ string'
    def Encodings.q_value_decode(str)
      RubyVer.q_value_decode(str)
    end

    def Encodings.split_encoding_from_string( str )
      match = str.match(/\=\?([^?]+)?\?[QB]\?(.+)?\?\=/mi)
      if match
        match[1]
      else
        nil
      end
    end

    def Encodings.find_encoding(str)
      RUBY_VERSION >= '1.9' ? str.encoding : $KCODE
    end
  end
end
