# encoding: utf-8

module Mail
  class Ruby19

    # Escapes any parenthesis in a string that are unescaped this uses
    # a Ruby 1.9.1 regexp feature of negative look behind
    def Ruby19.escape_paren( str )
      re = /(?<!\\)([\(\)])/          # Only match unescaped parens
      str.gsub(re) { |s| '\\' + s }
    end

    def Ruby19.paren( str )
      str = $1 if str =~ /^\((.*)?\)$/
      str = escape_paren( str )
      '(' + str + ')'
    end

    def Ruby19.escape_bracket( str )
      re = /(?<!\\)([\<\>])/          # Only match unescaped brackets
      str.gsub(re) { |s| '\\' + s }
    end

    def Ruby19.bracket( str )
      str = $1 if str =~ /^\<(.*)?\>$/
      str = escape_bracket( str )
      '<' + str + '>'
    end

    def Ruby19.decode_base64(str)
      str.unpack( 'm' ).first
    end

    def Ruby19.encode_base64(str)
      [str].pack( 'm' )
    end

    def Ruby19.has_constant?(klass, string)
      klass.const_defined?( string, false )
    end

    def Ruby19.get_constant(klass, string)
      klass.const_get( string )
    end

    def Ruby19.b_value_encode(str, encoding = nil)
      encoding = str.encoding.to_s
      [Ruby19.encode_base64(str), encoding]
    end

    def Ruby19.b_value_decode(str)
      match = str.match(/\=\?(.+)?\?[Bb]\?(.+)?\?\=/m)
      if match
        encoding = match[1]
        str = Ruby19.decode_base64(match[2])
        str.force_encoding(fix_encoding(encoding))
      end
      decoded = str.encode("utf-8", :invalid => :replace, :replace => "")
      decoded.valid_encoding? ? decoded : decoded.encode("utf-16le", :invalid => :replace, :replace => "").encode("utf-8")
    end

    def Ruby19.q_value_encode(str, encoding = nil)
      encoding = str.encoding.to_s
      [Encodings::QuotedPrintable.encode(str), encoding]
    end

    def Ruby19.q_value_decode(str)
      match = str.match(/\=\?(.+)?\?[Qq]\?(.+)?\?\=/m)
      if match
        encoding = match[1]
        str = Encodings::QuotedPrintable.decode(match[2].gsub(/_/, '=20'))
        str.force_encoding(fix_encoding(encoding))
      end
      decoded = str.encode("utf-8", :invalid => :replace, :replace => "")
      decoded.valid_encoding? ? decoded : decoded.encode("utf-16le", :invalid => :replace, :replace => "").encode("utf-8")
    end

    def Ruby19.param_decode(str, encoding)
      string = uri_parser.unescape(str)
      string.force_encoding(encoding) if encoding
      string
    end

    def Ruby19.param_encode(str)
      encoding = str.encoding.to_s.downcase
      language = Configuration.instance.param_encode_language
      "#{encoding}'#{language}'#{uri_parser.escape(str)}"
    end

    def Ruby19.uri_parser
      @uri_parser ||= URI::Parser.new
    end

     # mails somtimes includes invalid encodings like iso885915 or utf8 so we transform them to iso885915 or utf8
     # TODO: add this as a test somewhere
     # Encoding.list.map{|e| [e.to_s.upcase==fix_encoding(e.to_s.downcase.gsub("-", "")), e.to_s] }.select {|a,b| !b}
     #  Encoding.list.map{|e| [e.to_s==fix_encoding(e.to_s), e.to_s] }.select {|a,b| !b}
    def Ruby19.fix_encoding(encoding)
      case encoding
        # ISO-8859-15, ISO-2022-JP and alike
        when /iso-?(\d{4})-?(\w{1,2})/i then return "ISO-#{$1}-#{$2}"
        # "ISO-2022-JP-KDDI"  and alike
        when /iso-?(\d{4})-?(\w{1,2})-?(\w*)/i then return "ISO-#{$1}-#{$2}-#{$3}"
        # UTF-8, UTF-32BE and alike
        when /utf-?(\d{1,2})?(\w{1,2})/i then return "UTF-#{$1}#{$2}".gsub(/\A(UTF-(?:16|32))\z/, '\\1BE')
        # Windows-1252 and alike
        when /Windows-?(.*)/i then return "Windows-#{$1}"
        #more aliases to be added if needed
        else return encoding
      end
    end
  end
end
