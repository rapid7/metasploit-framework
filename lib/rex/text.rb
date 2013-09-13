# -*- coding: binary -*-
require 'digest/md5'
require 'digest/sha1'
require 'stringio'
require 'cgi'

%W{ iconv zlib }.each do |libname|
  begin
    old_verbose = $VERBOSE
    $VERBOSE = nil
    require libname
  rescue ::LoadError
  ensure
    $VERBOSE = old_verbose
  end
end

module Rex

###
#
# This class formats text in various fashions and also provides
# a mechanism for wrapping text at a given column.
#
###
module Text
  @@codepage_map_cache = nil

  ##
  #
  # Constants
  #
  ##

  States = ["AK", "AL", "AR", "AZ", "CA", "CO", "CT", "DE", "FL", "GA", "HI",
    "IA", "ID", "IL", "IN", "KS", "KY", "LA", "MA", "MD", "ME", "MI", "MN",
    "MO", "MS", "MT", "NC", "ND", "NE", "NH", "NJ", "NM", "NV", "NY", "OH",
    "OK", "OR", "PA", "RI", "SC", "SD", "TN", "TX", "UT", "VA", "VT", "WA",
    "WI", "WV", "WY"]
  UpperAlpha   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  LowerAlpha   = "abcdefghijklmnopqrstuvwxyz"
  Numerals     = "0123456789"
  Base32	     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  Alpha	     = UpperAlpha + LowerAlpha
  AlphaNumeric = Alpha + Numerals
  HighAscii    = [*(0x80 .. 0xff)].pack("C*")
  LowAscii     = [*(0x00 .. 0x1f)].pack("C*")
  DefaultWrap  = 60
  AllChars     = [*(0x00 .. 0xff)].pack("C*")
  Punctuation  = ( [*(0x21 .. 0x2f)] + [*(0x3a .. 0x3F)] + [*(0x5b .. 0x60)] + [*(0x7b .. 0x7e)] ).flatten.pack("C*")

  DefaultPatternSets = [ Rex::Text::UpperAlpha, Rex::Text::LowerAlpha, Rex::Text::Numerals ]

  # In case Iconv isn't loaded
  Iconv_EBCDIC = [
    "\x00", "\x01", "\x02", "\x03", "7", "-", ".", "/", "\x16", "\x05",
    "%", "\v", "\f", "\r", "\x0E", "\x0F", "\x10", "\x11", "\x12", "\x13",
    "<", "=", "2", "&", "\x18", "\x19", "?", "'", "\x1C", "\x1D", "\x1E",
    "\x1F", "@", "Z", "\x7F", "{", "[", "l", "P", "}", "M", "]", "\\",
    "N", "k", "`", "K", "a", "\xF0", "\xF1", "\xF2", "\xF3", "\xF4",
    "\xF5", "\xF6", "\xF7", "\xF8", "\xF9", "z", "^", "L", "~", "n", "o",
    "|", "\xC1", "\xC2", "\xC3", "\xC4", "\xC5", "\xC6", "\xC7", "\xC8",
    "\xC9", "\xD1", "\xD2", "\xD3", "\xD4", "\xD5", "\xD6", "\xD7",
    "\xD8", "\xD9", "\xE2", "\xE3", "\xE4", "\xE5", "\xE6", "\xE7",
    "\xE8", "\xE9", nil, "\xE0", nil, nil, "m", "y", "\x81", "\x82",
    "\x83", "\x84", "\x85", "\x86", "\x87", "\x88", "\x89", "\x91",
    "\x92", "\x93", "\x94", "\x95", "\x96", "\x97", "\x98", "\x99",
    "\xA2", "\xA3", "\xA4", "\xA5", "\xA6", "\xA7", "\xA8", "\xA9",
    "\xC0", "O", "\xD0", "\xA1", "\a", nil, nil, nil, nil, nil, nil,
    nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
    nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
    nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
    nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
    nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
    nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
    nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
    nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
    nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
    nil, nil, nil, nil, nil
  ]

  Iconv_ASCII  = [
    "\x00", "\x01", "\x02", "\x03", "\x04", "\x05", "\x06", "\a", "\b",
    "\t", "\n", "\v", "\f", "\r", "\x0E", "\x0F", "\x10", "\x11", "\x12",
    "\x13", "\x14", "\x15", "\x16", "\x17", "\x18", "\x19", "\x1A", "\e",
    "\x1C", "\x1D", "\x1E", "\x1F", " ", "!", "\"", "#", "$", "%", "&",
    "'", "(", ")", "*", "+", ",", "-", ".", "/", "0", "1", "2", "3", "4",
    "5", "6", "7", "8", "9", ":", ";", "<", "=", ">", "?", "@", "A", "B",
    "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P",
    "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", nil, "\\", nil,
    nil, "_", "`", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k",
    "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y",
    "z", "{", "|", "}", "~", "\x7F", nil, nil, nil, nil, nil, nil, nil,
    nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
    nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
    nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
    nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
    nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
    nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
    nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
    nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
    nil, nil, nil, nil, nil, nil, nil, nil, nil
  ]

  ##
  #
  # Serialization
  #
  ##

  #
  # Converts a raw string into a ruby buffer
  #
  def self.to_ruby(str, wrap = DefaultWrap, name = "buf")
    return hexify(str, wrap, '"', '" +', "#{name} = \n", '"')
  end

  #
  # Creates a ruby-style comment
  #
  def self.to_ruby_comment(str, wrap = DefaultWrap)
    return wordwrap(str, 0, wrap, '', '# ')
  end

  #
  # Converts a raw string into a C buffer
  #
  def self.to_c(str, wrap = DefaultWrap, name = "buf")
    return hexify(str, wrap, '"', '"', "unsigned char #{name}[] = \n", '";')
  end

  def self.to_csharp(str, wrap = DefaultWrap, name = "buf")
    ret = "byte[] #{name} = new byte[#{str.length}] {"
    i = -1;
    while (i += 1) < str.length
      ret << "\n" if i%(wrap/4) == 0
      ret << "0x" << str[i].unpack("H*")[0] << ","
    end
    ret = ret[0..ret.length-2] #cut off last comma
    ret << " };\n"
  end

  #
  # Creates a c-style comment
  #
  def self.to_c_comment(str, wrap = DefaultWrap)
    return "/*\n" + wordwrap(str, 0, wrap, '', ' * ') + " */\n"
  end

  #
  # Creates a javascript-style comment
  #
  def self.to_js_comment(str, wrap = DefaultWrap)
    return wordwrap(str, 0, wrap, '', '// ')
  end

  #
  # Converts a raw string into a perl buffer
  #
  def self.to_perl(str, wrap = DefaultWrap, name = "buf")
    return hexify(str, wrap, '"', '" .', "my $#{name} = \n", '";')
  end

  #
  # Converts a raw string into a python buffer
  #
  def self.to_python(str, wrap = DefaultWrap, name = "buf")
    return hexify(str, wrap, "#{name} += \"", '"', "#{name} =  \"\"\n", '"')
  end

  #
  # Converts a raw string into a Bash buffer
  #
  def self.to_bash(str, wrap = DefaultWrap, name = "buf")
    return hexify(str, wrap, '$\'', '\'\\', "export #{name}=\\\n", '\'')
  end

  #
  # Converts a raw string into a java byte array
  #
  def self.to_java(str, name = "shell")
    buff = "byte #{name}[] = new byte[]\n{\n"
    cnt = 0
    max = 0
    str.unpack('C*').each do |c|
      buff << ", " if max > 0
      buff << "\t" if max == 0
      buff << sprintf('(byte) 0x%.2x', c)
      max +=1
      cnt +=1

      if (max > 7)
        buff << ",\n" if cnt != str.length
        max = 0
      end
    end
    buff << "\n};\n"
    return buff
  end

  #
  # Converts a raw string to a powershell byte array
  #
  def self.to_powershell(str, name = "buf")
    return "[Byte[]]$#{name} = ''" if str.nil? or str.empty?

    code = str.unpack('C*')
    buff = "[Byte[]]$#{name} = 0x#{code[0].to_s(16)}"
    1.upto(code.length-1) do |byte|
      if(byte % 10 == 0)
        buff << "\r\n$#{name} += 0x#{code[byte].to_s(16)}"
      else
        buff << ",0x#{code[byte].to_s(16)}"
      end
    end

    return buff
  end

  #
  # Converts a raw string to a vbscript byte array
  #
  def self.to_vbscript(str, name = "buf")
    return "#{name}" if str.nil? or str.empty?

    code = str.unpack('C*')
    buff = "#{name}=Chr(#{code[0]})"
    1.upto(code.length-1) do |byte|
      if(byte % 100 == 0)
        buff << "\r\n#{name}=#{name}"
      end
      # exe is an Array of bytes, not a String, thanks to the unpack
      # above, so the following line is not subject to the different
      # treatments of String#[] between ruby 1.8 and 1.9
      buff << "&Chr(#{code[byte]})"
    end

    return buff
  end

  #
  # Converts a raw string into a vba buffer
  #
  def self.to_vbapplication(str, name = "buf")
    return "#{name} = Array()" if str.nil? or str.empty?

    code  = str.unpack('C*')
    buff = "#{name} = Array("
    maxbytes = 20

    1.upto(code.length) do |idx|
      buff << code[idx].to_s
      buff << "," if idx < code.length - 1
      buff << " _\r\n" if (idx > 1 and (idx % maxbytes) == 0)
    end

    buff << ")\r\n"

    return buff
  end

  #
  # Creates a perl-style comment
  #
  def self.to_perl_comment(str, wrap = DefaultWrap)
    return wordwrap(str, 0, wrap, '', '# ')
  end

  #
  # Creates a Bash-style comment
  #
  def self.to_bash_comment(str, wrap = DefaultWrap)
    return wordwrap(str, 0, wrap, '', '# ')
  end

  #
  # Returns the raw string
  #
  def self.to_raw(str)
    return str
  end

  #
  # Converts ISO-8859-1 to UTF-8
  #
  def self.to_utf8(str)

    if str.respond_to?(:encode)
      # Skip over any bytes that fail to convert to UTF-8
      return str.encode('utf-8', { :invalid => :replace, :undef => :replace, :replace => '' })
    end

    begin
      Iconv.iconv("utf-8","iso-8859-1", str).join(" ")
    rescue
      raise ::RuntimeError, "Your installation does not support iconv (needed for utf8 conversion)"
    end
  end

  #
  # Converts ASCII to EBCDIC
  #
  class IllegalSequence < ArgumentError; end

  # A native implementation of the ASCII->EBCDIC table, used to fall back from using
  # Iconv
  def self.to_ebcdic_rex(str)
    new_str = []
    str.each_byte do |x|
      if Iconv_ASCII.index(x.chr)
        new_str << Iconv_EBCDIC[Iconv_ASCII.index(x.chr)]
      else
        raise Rex::Text::IllegalSequence, ("\\x%x" % x)
      end
    end
    new_str.join
  end

  # A native implementation of the EBCDIC->ASCII table, used to fall back from using
  # Iconv
  def self.from_ebcdic_rex(str)
    new_str = []
    str.each_byte do |x|
      if Iconv_EBCDIC.index(x.chr)
        new_str << Iconv_ASCII[Iconv_EBCDIC.index(x.chr)]
      else
        raise Rex::Text::IllegalSequence, ("\\x%x" % x)
      end
    end
    new_str.join
  end

  def self.to_ebcdic(str)
    begin
      Iconv.iconv("EBCDIC-US", "ASCII", str).first
    rescue ::Iconv::IllegalSequence => e
      raise e
    rescue
      self.to_ebcdic_rex(str)
    end
  end

  #
  # Converts EBCIDC to ASCII
  #
  def self.from_ebcdic(str)
    begin
      Iconv.iconv("ASCII", "EBCDIC-US", str).first
    rescue ::Iconv::IllegalSequence => e
      raise e
    rescue
      self.from_ebcdic_rex(str)
    end
  end

  #
  # Returns the words in +str+ as an Array.
  #
  # strict - include *only* words, no boundary characters (like spaces, etc.)
  #
  def self.to_words( str, strict = false )
    splits = str.split( /\b/ )
    splits.reject! { |w| !(w =~ /\w/) } if strict
    splits
  end

  #
  # Removes noise from 2 Strings and return a refined String version.
  #
  def self.refine( str1, str2 )
    return str1 if str1 == str2

    # get the words of the first str in an array
    s_words = to_words( str1 )

    # get the words of the second str in an array
    o_words = to_words( str2 )

    # get what hasn't changed (the rdiff, so to speak) as a string
    (s_words - (s_words - o_words)).join
  end

  #
  # Returns a unicode escaped string for Javascript
  #
  def self.to_unescape(data, endian=ENDIAN_LITTLE)
    data << "\x41" if (data.length % 2 != 0)
    dptr = 0
    buff = ''
    while (dptr < data.length)
      c1 = data[dptr,1].unpack("C*")[0]
      dptr += 1
      c2 = data[dptr,1].unpack("C*")[0]
      dptr += 1

      if (endian == ENDIAN_LITTLE)
        buff << sprintf('%%u%.2x%.2x', c2, c1)
      else
        buff << sprintf('%%u%.2x%.2x', c1, c2)
      end
    end
    return buff
  end

  #
  # Returns the escaped octal version of the supplied string
  #
  # @example
  #   Rex::Text.to_octal("asdf") # => "\\141\\163\\144\\146"
  #
  # @param str [String] The string to be converted
  # @param prefix [String]
  # @return [String] The escaped octal version of +str+
  def self.to_octal(str, prefix = "\\")
    octal = ""
    str.each_byte { |b|
      octal << "#{prefix}#{b.to_s 8}"
    }

    return octal
  end

  #
  # Returns the escaped hex version of the supplied string
  #
  # @example
  #   Rex::Text.to_hex("asdf") # => "\\x61\\x73\\x64\\x66"
  #
  # @param str (see to_octal)
  # @param prefix (see to_octal)
  # @param count [Fixnum] Number of bytes to put in each escape chunk
  # @return [String] The escaped hex version of +str+
  def self.to_hex(str, prefix = "\\x", count = 1)
    raise ::RuntimeError, "unable to chunk into #{count} byte chunks" if ((str.length % count) > 0)

    # XXX: Regexp.new is used here since using /.{#{count}}/o would compile
    # the regex the first time it is used and never check again.  Since we
    # want to know how many to capture on every instance, we do it this
    # way.
    return str.unpack('H*')[0].gsub(Regexp.new(".{#{count * 2}}", nil, 'n')) { |s| prefix + s }
  end

  #
  # Returns the string with nonprintable hex characters sanitized to ascii.
  # Similiar to {.to_hex}, but regular ASCII is not translated if +count+ is 1.
  #
  # @example
  #   Rex::Text.to_hex_ascii("\x7fABC\0") # => "\\x7fABC\\x00"
  #
  # @param str (see to_hex)
  # @param prefix (see to_hex)
  # @param count (see to_hex)
  # @param suffix [String,nil] A string to append to the converted bytes
  # @return [String] The original string with non-printables converted to
  #   their escaped hex representation
  def self.to_hex_ascii(str, prefix = "\\x", count = 1, suffix=nil)
    raise ::RuntimeError, "unable to chunk into #{count} byte chunks" if ((str.length % count) > 0)
    return str.unpack('H*')[0].gsub(Regexp.new(".{#{count * 2}}", nil, 'n')) { |s|
      (0x20..0x7e) === s.to_i(16) ? s.to_i(16).chr : prefix + s + suffix.to_s
    }
  end

  #
  # Converts standard ASCII text to a unicode string.
  #
  # Supported unicode types include: utf-16le, utf16-be, utf32-le,
  # utf32-be, utf-7, and utf-8
  #
  # Providing 'mode' provides hints to the actual encoder as to how it
  # should encode the string.
  #
  # Only UTF-7 and UTF-8 use "mode".
  #
  # utf-7 by default does not encode alphanumeric and a few other
  # characters.  By specifying the mode of "all", then all of the
  # characters are encoded, not just the non-alphanumeric set.
  # to_unicode(str, 'utf-7', 'all')
  #
  # utf-8 specifies that alphanumeric characters are used directly, eg
  # "a" is just "a".  However, there exist 6 different overlong
  # encodings of "a" that are technically not valid, but parse just fine
  # in most utf-8 parsers.  (0xC1A1, 0xE081A1, 0xF08081A1, 0xF8808081A1,
  # 0xFC80808081A1, 0xFE8080808081A1).  How many bytes to use for the
  # overlong enocding is specified providing 'size'.  to_unicode(str,
  # 'utf-8', 'overlong', 2)
  #
  # Many utf-8 parsers also allow invalid overlong encodings, where bits
  # that are unused when encoding a single byte are modified.  Many
  # parsers will ignore these bits, rendering simple string matching to
  # be ineffective for dealing with UTF-8 strings.  There are many more
  # invalid overlong encodings possible for "a".  For example, three
  # encodings are available for an invalid 2 byte encoding of "a".
  # (0xC1E1 0xC161 0xC121).
  #
  # By specifying "invalid", a random invalid encoding is chosen for the
  # given byte size.  to_unicode(str, 'utf-8', 'invalid', 2)
  #
  # utf-7 defaults to 'normal' utf-7 encoding utf-8 defaults to 2 byte
  # 'normal' encoding
  def self.to_unicode(str='', type = 'utf-16le', mode = '', size = '')
    return '' if not str
    case type
    when 'utf-16le'
      return str.unpack('C*').pack('v*')
    when 'utf-16be'
      return str.unpack('C*').pack('n*')
    when 'utf-32le'
      return str.unpack('C*').pack('V*')
    when 'utf-32be'
      return str.unpack('C*').pack('N*')
    when 'utf-7'
      case mode
      when 'all'
        return str.gsub(/./){ |a|
          out = ''
          if 'a' != '+'
            out = encode_base64(to_unicode(a, 'utf-16be')).gsub(/[=\r\n]/, '')
          end
          '+' + out + '-'
        }
      else
        return str.gsub(/[^\n\r\t\ A-Za-z0-9\'\(\),-.\/\:\?]/){ |a|
          out = ''
          if a != '+'
            out = encode_base64(to_unicode(a, 'utf-16be')).gsub(/[=\r\n]/, '')
          end
          '+' + out + '-'
        }
      end
    when 'utf-8'
      if size == ''
        size = 2
      end

      if size >= 2 and size <= 7
        string = ''
        str.each_byte { |a|
          if (a < 21 || a > 0x7f) || mode != ''
            # ugh.	turn a single byte into the binary representation of it, in array form
            bin = [a].pack('C').unpack('B8')[0].split(//)

            # even more ugh.
            bin.collect!{|a_| a_.to_i}

            out = Array.new(8 * size, 0)

            0.upto(size - 1) { |i|
              out[i] = 1
              out[i * 8] = 1
            }

            i = 0
            byte = 0
            bin.reverse.each { |bit|
              if i < 6
                mod = (((size * 8) - 1) - byte * 8) - i
                out[mod] = bit
              else
                byte = byte + 1
                i = 0
                redo
              end
              i = i + 1
            }

            if mode != ''
              case mode
              when 'overlong'
                # do nothing, since we already handle this as above...
              when 'invalid'
                done = 0
                while done == 0
                  # the ghetto...
                  bits = [7, 8, 15, 16, 23, 24, 31, 32, 41]
                  bits.each { |bit|
                    bit = (size * 8) - bit
                    if bit > 1
                      set = rand(2)
                      if out[bit] != set
                        out[bit] = set
                        done = 1
                      end
                    end
                  }
                end
              else
                raise TypeError, 'Invalid mode.  Only "overlong" and "invalid" are acceptable modes for utf-8'
              end
            end
            string << [out.join('')].pack('B*')
          else
            string << [a].pack('C')
          end
        }
        return string
      else
        raise TypeError, 'invalid utf-8 size'
      end
    when 'uhwtfms' # suggested name from HD :P
      load_codepage()

      string = ''
      # overloading mode as codepage
      if mode == ''
        mode = 1252 # ANSI - Latan 1, default for US installs of MS products
      else
        mode = mode.to_i
      end
      if @@codepage_map_cache[mode].nil?
        raise TypeError, "Invalid codepage #{mode}"
      end
      str.each_byte {|byte|
        char = [byte].pack('C*')
        possible = @@codepage_map_cache[mode]['data'][char]
        if possible.nil?
          raise TypeError, "codepage #{mode} does not provide an encoding for 0x#{char.unpack('H*')[0]}"
        end
        string << possible[ rand(possible.length) ]
      }
      return string
    when 'uhwtfms-half' # suggested name from HD :P
      load_codepage()
      string = ''
      # overloading mode as codepage
      if mode == ''
        mode = 1252 # ANSI - Latan 1, default for US installs of MS products
      else
        mode = mode.to_i
      end
      if mode != 1252
        raise TypeError, "Invalid codepage #{mode}, only 1252 supported for uhwtfms_half"
      end
      str.each_byte {|byte|
        if ((byte >= 33 && byte <= 63) || (byte >= 96 && byte <= 126))
          string << "\xFF" + [byte ^ 32].pack('C')
        elsif (byte >= 64 && byte <= 95)
          string << "\xFF" + [byte ^ 96].pack('C')
        else
          char = [byte].pack('C')
          possible = @@codepage_map_cache[mode]['data'][char]
          if possible.nil?
            raise TypeError, "codepage #{mode} does not provide an encoding for 0x#{char.unpack('H*')[0]}"
          end
          string << possible[ rand(possible.length) ]
        end
      }
      return string
    else
      raise TypeError, 'invalid utf type'
    end
  end

  #
  # Converts a unicode string to standard ASCII text.
  #
  def self.to_ascii(str='', type = 'utf-16le', mode = '', size = '')
    return '' if not str
    case type
    when 'utf-16le'
      return str.unpack('v*').pack('C*')
    when 'utf-16be'
      return str.unpack('n*').pack('C*')
    when 'utf-32le'
      return str.unpack('V*').pack('C*')
    when 'utf-32be'
      return str.unpack('N*').pack('C*')
    when 'utf-7'
      raise TypeError, 'invalid utf type, not yet implemented'
    when 'utf-8'
      raise TypeError, 'invalid utf type, not yet implemented'
    when 'uhwtfms' # suggested name from HD :P
      raise TypeError, 'invalid utf type, not yet implemented'
    when 'uhwtfms-half' # suggested name from HD :P
      raise TypeError, 'invalid utf type, not yet implemented'
    else
      raise TypeError, 'invalid utf type'
    end
  end

  #
  # Encode a string in a manor useful for HTTP URIs and URI Parameters.
  #
  def self.uri_encode(str, mode = 'hex-normal')
    return "" if str == nil

    return str if mode == 'none' # fast track no encoding

    all = /[^\/\\]+/
    normal = /[^a-zA-Z0-9\/\\\.\-]+/
    normal_na = /[a-zA-Z0-9\/\\\.\-]/

    case mode
    when 'hex-normal'
      return str.gsub(normal) { |s| Rex::Text.to_hex(s, '%') }
    when 'hex-all'
      return str.gsub(all) { |s| Rex::Text.to_hex(s, '%') }
    when 'hex-random'
      res = ''
      str.each_byte do |c|
        b = c.chr
        res << ((rand(2) == 0) ?
          b.gsub(all)   { |s| Rex::Text.to_hex(s, '%') } :
          b.gsub(normal){ |s| Rex::Text.to_hex(s, '%') } )
      end
      return res
    when 'u-normal'
      return str.gsub(normal) { |s| Rex::Text.to_hex(Rex::Text.to_unicode(s, 'uhwtfms'), '%u', 2) }
    when 'u-all'
      return str.gsub(all) { |s| Rex::Text.to_hex(Rex::Text.to_unicode(s, 'uhwtfms'), '%u', 2) }
    when 'u-random'
      res = ''
      str.each_byte do |c|
        b = c.chr
        res << ((rand(2) == 0) ?
          b.gsub(all)   { |s| Rex::Text.to_hex(Rex::Text.to_unicode(s, 'uhwtfms'), '%u', 2) } :
          b.gsub(normal){ |s| Rex::Text.to_hex(Rex::Text.to_unicode(s, 'uhwtfms'), '%u', 2) } )
      end
      return res
    when 'u-half'
      return str.gsub(all) { |s| Rex::Text.to_hex(Rex::Text.to_unicode(s, 'uhwtfms-half'), '%u', 2) }
    else
      raise TypeError, "invalid mode #{mode.inspect}"
    end
  end

  #
  # Encode a string in a manner useful for HTTP URIs and URI Parameters.
  #
  # @param str [String] The string to be encoded
  # @param mode ["hex","int","int-wide"]
  # @return [String]
  # @raise [TypeError] if +mode+ is not one of the three available modes
  def self.html_encode(str, mode = 'hex')
    case mode
    when 'hex'
      return str.unpack('C*').collect{ |i| "&#x" + ("%.2x" % i) + ";"}.join
    when 'int'
      return str.unpack('C*').collect{ |i| "&#" + i.to_s + ";"}.join
    when 'int-wide'
      return str.unpack('C*').collect{ |i| "&#" + ("0" * (7 - i.to_s.length)) + i.to_s + ";" }.join
    else
      raise TypeError, 'invalid mode'
    end
  end

  #
  # Decode a string that's html encoded
  #
  def self.html_decode(str)
    decoded_str = CGI.unescapeHTML(str)
    return decoded_str
  end

  #
  # Encode an ASCII string so it's safe for XML. It's a wrapper for to_hex_ascii.
  #
  def self.xml_char_encode(str)
    self.to_hex_ascii(str, "&#x", 1, ";")
  end

  #
  # Decode a URI encoded string
  #
  def self.uri_decode(str)
    str.gsub(/(%[a-z0-9]{2})/i){ |c| [c[1,2]].pack("H*") }
  end

  #
  # Converts a string to random case
  #
  # @example
  #   Rex::Text.to_rand_case("asdf") # => "asDf"
  #
  # @param str [String] The string to randomize
  # @return [String]
  # @see permute_case
  # @see to_mixed_case_array
  def self.to_rand_case(str)
    buf = str.dup
    0.upto(str.length) do |i|
      buf[i,1] = rand(2) == 0 ? str[i,1].upcase : str[i,1].downcase
    end
    return buf
  end

  #
  # Takes a string, and returns an array of all mixed case versions.
  #
  # @example
  #   >> Rex::Text.to_mixed_case_array "abc1"
  #   => ["abc1", "abC1", "aBc1", "aBC1", "Abc1", "AbC1", "ABc1", "ABC1"]
  #
  # @param str [String] The string to randomize
  # @return [Array<String>]
  # @see permute_case
  def self.to_mixed_case_array(str)
    letters = []
    str.scan(/./).each { |l| letters << [l.downcase, l.upcase] }
    coords = []
    (1 << str.size).times { |i| coords << ("%0#{str.size}b" % i) }
    mixed = []
    coords.each do |coord|
      c = coord.scan(/./).map {|x| x.to_i}
      this_str = ""
      c.each_with_index { |d,i| this_str << letters[i][d] }
      mixed << this_str
    end
    return mixed.uniq
  end

  #
  # Converts a string to a nicely formatted hex dump
  #
  # @param str [String] The string to convert
  # @param width [Fixnum] Number of bytes to convert before adding a newline
  # @param base [Fixnum] The base address of the dump
  def self.to_hex_dump(str, width=16, base=nil)
    buf = ''
    idx = 0
    cnt = 0
    snl = false
    lst = 0
    lft_col_len = (base.to_i+str.length).to_s(16).length
    lft_col_len = 8 if lft_col_len < 8

    while (idx < str.length)
      chunk = str[idx, width]
      addr = base ? "%0#{lft_col_len}x  " %(base.to_i + idx) : ''
      line  = chunk.unpack("H*")[0].scan(/../).join(" ")
      buf << addr + line

      if (lst == 0)
        lst = line.length
        buf << " " * 4
      else
        buf << " " * ((lst - line.length) + 4).abs
      end

      buf << "|"

      chunk.unpack("C*").each do |c|
        if (c >	0x1f and c < 0x7f)
          buf << c.chr
        else
          buf << "."
        end
      end

      buf << "|\n"

      idx += width
    end

    buf << "\n"
  end

  #
  # Converts a hex string to a raw string
  #
  # @example
  #   Rex::Text.hex_to_raw("\\x41\\x7f\\x42") # => "A\x7fB"
  #
  def self.hex_to_raw(str)
    [ str.downcase.gsub(/'/,'').gsub(/\\?x([a-f0-9][a-f0-9])/, '\1') ].pack("H*")
  end

  #
  # Turn non-printable chars into hex representations, leaving others alone
  #
  # If +whitespace+ is true, converts whitespace (0x20, 0x09, etc) to hex as
  # well.
  #
  # @see hexify
  # @see to_hex Converts all the chars
  #
  def self.ascii_safe_hex(str, whitespace=false)
    if whitespace
      str.gsub(/([\x00-\x20\x80-\xFF])/n){ |x| "\\x%.2x" % x.unpack("C*")[0] }
    else
      str.gsub(/([\x00-\x08\x0b\x0c\x0e-\x1f\x80-\xFF])/n){ |x| "\\x%.2x" % x.unpack("C*")[0]}
    end
  end

  #
  # Wraps text at a given column using a supplied indention
  #
  def self.wordwrap(str, indent = 0, col = DefaultWrap, append = '', prepend = '')
    return str.gsub(/.{1,#{col - indent}}(?:\s|\Z)/){
      ( (" " * indent) + prepend + $& + append + 5.chr).gsub(/\n\005/,"\n").gsub(/\005/,"\n")}
  end

  #
  # Converts a string to a hex version with wrapping support
  #
  def self.hexify(str, col = DefaultWrap, line_start = '', line_end = '', buf_start = '', buf_end = '')
    output	 = buf_start
    cur	 = 0
    count	 = 0
    new_line = true

    # Go through each byte in the string
    str.each_byte { |byte|
      count  += 1
      append	= ''

      # If this is a new line, prepend with the
      # line start text
      if (new_line == true)
        append	 << line_start
        new_line  = false
      end

      # Append the hexified version of the byte
      append << sprintf("\\x%.2x", byte)
      cur    += append.length

      # If we're about to hit the column or have gone past it,
      # time to finish up this line
      if ((cur + line_end.length >= col) or (cur + buf_end.length  >= col))
        new_line  = true
        cur	  = 0

        # If this is the last byte, use the buf_end instead of
        # line_end
        if (count == str.length)
          append << buf_end + "\n"
        else
          append << line_end + "\n"
        end
      end

      output << append
    }

    # If we were in the middle of a line, finish the buffer at this point
    if (new_line == false)
      output << buf_end + "\n"
    end

    return output
  end

  ##
  #
  # Transforms
  #
  ##

  #
  # Base32 code
  #

  # Based on --> https://github.com/stesla/base32

  # Copyright (c) 2007-2011 Samuel Tesla

  # Permission is hereby granted, free of charge, to any person obtaining a copy
  # of this software and associated documentation files (the "Software"), to deal
  # in the Software without restriction, including without limitation the rights
  # to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  # copies of the Software, and to permit persons to whom the Software is
  # furnished to do so, subject to the following conditions:

  # The above copyright notice and this permission notice shall be included in
  # all copies or substantial portions of the Software.

  # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  # IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  # FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  # AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  # LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  # OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  # THE SOFTWARE.


  #
  # Base32 encoder
  #
  def self.b32encode(bytes_in)
    n = (bytes_in.length * 8.0 / 5.0).ceil
    p = n < 8 ? 5 - (bytes_in.length * 8) % 5 : 0
    c = bytes_in.inject(0) {|m,o| (m << 8) + o} << p
    [(0..n-1).to_a.reverse.collect {|i| Base32[(c >> i * 5) & 0x1f].chr},
    ("=" * (8-n))]
  end

  def self.encode_base32(str)
    bytes = str.bytes
    result = ''
    size= 5
    while bytes.any? do
      bytes.each_slice(size) do |a|
      bytes_out = b32encode(a).flatten.join
      result << bytes_out
      bytes = bytes.drop(size)
      end
    end
    return result
  end

  #
  # Base32 decoder
  #
  def self.b32decode(bytes_in)
    bytes = bytes_in.take_while {|c| c != 61} # strip padding
    n = (bytes.length * 5.0 / 8.0).floor
    p = bytes.length < 8 ? 5 - (n * 8) % 5 : 0
    c = bytes.inject(0) {|m,o| (m << 5) + Base32.index(o.chr)} >> p
    (0..n-1).to_a.reverse.collect {|i| ((c >> i * 8) & 0xff).chr}
  end

  def self.decode_base32(str)
    bytes = str.bytes
    result = ''
    size= 8
    while bytes.any? do
      bytes.each_slice(size) do |a|
      bytes_out = b32decode(a).flatten.join
      result << bytes_out
      bytes = bytes.drop(size)
      end
    end
    return result
  end

  #
  # Base64 encoder
  #
  def self.encode_base64(str, delim='')
    [str.to_s].pack("m").gsub(/\s+/, delim)
  end

  #
  # Base64 decoder
  #
  def self.decode_base64(str)
    str.to_s.unpack("m")[0]
  end

  #
  # Raw MD5 digest of the supplied string
  #
  def self.md5_raw(str)
    Digest::MD5.digest(str)
  end

  #
  # Hexidecimal MD5 digest of the supplied string
  #
  def self.md5(str)
    Digest::MD5.hexdigest(str)
  end

  #
  # Raw SHA1 digest of the supplied string
  #
  def self.sha1_raw(str)
    Digest::SHA1.digest(str)
  end

  #
  # Hexidecimal SHA1 digest of the supplied string
  #
  def self.sha1(str)
    Digest::SHA1.hexdigest(str)
  end

  #
  # Convert hex-encoded characters to literals.
  #
  # @example
  #   Rex::Text.dehex("AA\\x42CC") # => "AABCC"
  #
  # @see hex_to_raw
  # @param str [String]
  def self.dehex(str)
    return str unless str.respond_to? :match
    return str unless str.respond_to? :gsub
    regex = /\x5cx[0-9a-f]{2}/nmi
    if str.match(regex)
      str.gsub(regex) { |x| x[2,2].to_i(16).chr }
    else
      str
    end
  end

  #
  # Convert and replace hex-encoded characters to literals.
  #
  # @param (see dehex)
  def self.dehex!(str)
    return str unless str.respond_to? :match
    return str unless str.respond_to? :gsub
    regex = /\x5cx[0-9a-f]{2}/nmi
    str.gsub!(regex) { |x| x[2,2].to_i(16).chr }
  end

  ##
  #
  # Generators
  #
  ##


  # Generates a random character.
  def self.rand_char(bad, chars = AllChars)
    rand_text(1, bad, chars)
  end

  # Base text generator method
  def self.rand_base(len, bad, *foo)
    cset = (foo.join.unpack("C*") - bad.to_s.unpack("C*")).uniq
    return "" if cset.length == 0
    outp = []
    len.times { outp << cset[rand(cset.length)] }
    outp.pack("C*")
  end

  # Generate random bytes of data
  def self.rand_text(len, bad='', chars = AllChars)
    foo = chars.split('')
    rand_base(len, bad, *foo)
  end

  # Generate random bytes of alpha data
  def self.rand_text_alpha(len, bad='')
    foo = []
    foo += ('A' .. 'Z').to_a
    foo += ('a' .. 'z').to_a
    rand_base(len, bad, *foo )
  end

  # Generate random bytes of lowercase alpha data
  def self.rand_text_alpha_lower(len, bad='')
    rand_base(len, bad, *('a' .. 'z').to_a)
  end

  # Generate random bytes of uppercase alpha data
  def self.rand_text_alpha_upper(len, bad='')
    rand_base(len, bad, *('A' .. 'Z').to_a)
  end

  # Generate random bytes of alphanumeric data
  def self.rand_text_alphanumeric(len, bad='')
    foo = []
    foo += ('A' .. 'Z').to_a
    foo += ('a' .. 'z').to_a
    foo += ('0' .. '9').to_a
    rand_base(len, bad, *foo )
  end

  # Generate random bytes of alphanumeric hex.
  def self.rand_text_hex(len, bad='')
    foo = []
    foo += ('0' .. '9').to_a
    foo += ('a' .. 'f').to_a
    rand_base(len, bad, *foo)
  end

  # Generate random bytes of numeric data
  def self.rand_text_numeric(len, bad='')
    foo = ('0' .. '9').to_a
    rand_base(len, bad, *foo )
  end

  # Generate random bytes of english-like data
  def self.rand_text_english(len, bad='')
    foo = []
    foo += (0x21 .. 0x7e).map{ |c| c.chr }
    rand_base(len, bad, *foo )
  end

  # Generate random bytes of high ascii data
  def self.rand_text_highascii(len, bad='')
    foo = []
    foo += (0x80 .. 0xff).map{ |c| c.chr }
    rand_base(len, bad, *foo )
  end

  # Generate a random GUID
  #
  # @example
  #   Rex::Text.rand_guid # => "{ca776ced-4ab8-2ed6-6510-aa71e5e2508e}"
  #
  # @return [String]
  def self.rand_guid
    "{#{[8,4,4,4,12].map {|a| rand_text_hex(a) }.join("-")}}"
  end

  #
  # Creates a pattern that can be used for offset calculation purposes.  This
  # routine is capable of generating patterns using a supplied set and a
  # supplied number of identifiable characters (slots).  The supplied sets
  # should not contain any duplicate characters or the logic will fail.
  #
  # @param length [Fixnum]
  # @param sets [Array<(String,String,String)>] The character sets to choose
  #   from. Should have 3 elements, each of which must be a string containing
  #   no characters contained in the other sets.
  # @return [String] A pattern of +length+ bytes, in which any 4-byte chunk is
  #   unique
  # @see pattern_offset
  def self.pattern_create(length, sets = nil)
    buf = ''
    offsets = []

    # Make sure there's something in sets even if we were given an explicit nil
    sets ||= [ UpperAlpha, LowerAlpha, Numerals ]

    # Return stupid uses
    return "" if length.to_i < 1
    return sets[0][0].chr * length if sets.size == 1 and sets[0].size == 1

    sets.length.times { offsets << 0 }

    until buf.length >= length
      begin
        buf << converge_sets(sets, 0, offsets, length)
      end
    end

    # Maximum permutations reached, but we need more data
    if (buf.length < length)
      buf = buf * (length / buf.length.to_f).ceil
    end

    buf[0,length]
  end

  # Step through an arbitrary number of sets of bytes to build up a findable pattern.
  # This is mostly useful for experimentially determining offset lengths into memory
  # structures. Note that the supplied sets should never contain duplicate bytes, or
  # else it can become impossible to measure the offset accurately.
  def self.patt2(len, sets = nil)
    buf = ""
    counter = []
    sets ||= [ UpperAlpha, LowerAlpha, Numerals ]
    len ||= len.to_i
    return "" if len.zero?

    sets = sets.map {|a| a.split(//)}
    sets.size.times { counter << 0}
    0.upto(len-1) do |i|
      setnum = i % sets.size

      #puts counter.inspect
    end

    return buf
  end

  #
  # Calculate the offset to a pattern
  #
  # @param pattern [String] The pattern to search. Usually the return value
  #   from {.pattern_create}
  # @param value [String,Fixnum,Bignum]
  # @return [Fixnum] Index of the given +value+ within +pattern+, if it exists
  # @return [nil] if +pattern+ does not contain +value+
  # @see pattern_create
  def self.pattern_offset(pattern, value, start=0)
    if (value.kind_of?(String))
      pattern.index(value, start)
    elsif (value.kind_of?(Fixnum) or value.kind_of?(Bignum))
      pattern.index([ value ].pack('V'), start)
    else
      raise ::ArgumentError, "Invalid class for value: #{value.class}"
    end
  end

  #
  # Compresses a string, eliminating all superfluous whitespace before and
  # after lines and eliminating all lines.
  #
  # @param str [String] The string in which to crunch whitespace
  # @return [String] Just like +str+, but with repeated whitespace characters
  #   trimmed down to a single space
  def self.compress(str)
    str.gsub(/\n/m, ' ').gsub(/\s+/, ' ').gsub(/^\s+/, '').gsub(/\s+$/, '')
  end

  #
  # Randomize the whitespace in a string
  #
  def self.randomize_space(str)
    str.gsub(/\s+/) { |s|
      len = rand(50)+2
      set = "\x09\x20\x0d\x0a"
      buf = ''
      while (buf.length < len)
        buf << set[rand(set.length),1]
      end

      buf
    }
  end

  # Returns true if zlib can be used.
  def self.zlib_present?
    begin
      temp = Zlib
      return true
    rescue
      return false
    end
  end

  # backwards compat for just a bit...
  def self.gzip_present?
    self.zlib_present?
  end

  #
  # Compresses a string using zlib
  #
  # @param str [String] The string to be compressed
  # @param level [Fixnum] One of the Zlib compression level constants
  # @return [String] The compressed version of +str+
  def self.zlib_deflate(str, level = Zlib::BEST_COMPRESSION)
    if self.zlib_present?
      z = Zlib::Deflate.new(level)
      dst = z.deflate(str, Zlib::FINISH)
      z.close
      return dst
    else
      raise RuntimeError, "Gzip support is not present."
    end
  end

  #
  # Uncompresses a string using zlib
  #
  # @param str [String] Compressed string to inflate
  # @return [String] The uncompressed version of +str+
  def self.zlib_inflate(str)
    if(self.zlib_present?)
      zstream = Zlib::Inflate.new
      buf = zstream.inflate(str)
      zstream.finish
      zstream.close
      return buf
    else
      raise RuntimeError, "Gzip support is not present."
    end
  end

  #
  # Compresses a string using gzip
  #
  # @param str (see zlib_deflate)
  # @param level [Fixnum] Compression level, 1 (fast) to 9 (best)
  # @return (see zlib_deflate)
  def self.gzip(str, level = 9)
    raise RuntimeError, "Gzip support is not present." if (!zlib_present?)
    raise RuntimeError, "Invalid gzip compression level" if (level < 1 or level > 9)

    s = ""
    s.force_encoding('ASCII-8BIT') if s.respond_to?(:encoding)
    gz = Zlib::GzipWriter.new(StringIO.new(s, 'wb'), level)
    gz << str
    gz.close
    return s
  end

  #
  # Uncompresses a string using gzip
  #
  # @param str (see zlib_inflate)
  # @return (see zlib_inflate)
  def self.ungzip(str)
    raise RuntimeError, "Gzip support is not present." if (!zlib_present?)

    s = ""
    s.force_encoding('ASCII-8BIT') if s.respond_to?(:encoding)
    gz = Zlib::GzipReader.new(StringIO.new(str, 'rb'))
    s << gz.read
    gz.close
    return s
  end

  #
  # Return the index of the first badchar in +data+, otherwise return
  # nil if there wasn't any badchar occurences.
  #
  # @param data [String] The string to check for bad characters
  # @param badchars [String] A list of characters considered to be bad
  # @return [Fixnum] Index of the first bad character if any exist in +data+
  # @return [nil] If +data+ contains no bad characters
  def self.badchar_index(data, badchars = '')
    badchars.unpack("C*").each { |badchar|
      pos = data.index(badchar.chr)
      return pos if pos
    }
    return nil
  end

  #
  # Removes bad characters from a string.
  #
  # Modifies +data+ in place
  #
  # @param data [#delete]
  # @param badchars [String] A list of characters considered to be bad
  def self.remove_badchars(data, badchars = '')
    data.delete(badchars)
  end

  #
  # Returns all chars that are not in the supplied set
  #
  # @param keepers [String]
  # @return [String] All characters not contained in +keepers+
  def self.charset_exclude(keepers)
    [*(0..255)].pack('C*').delete(keepers)
  end

  #
  # Shuffles a byte stream
  #
  # @param str [String]
  # @return [String] The shuffled result
  # @see shuffle_a
  def self.shuffle_s(str)
    shuffle_a(str.unpack("C*")).pack("C*")
  end

  #
  # Performs a Fisher-Yates shuffle on an array
  #
  # Modifies +arr+ in place
  #
  # @param arr [Array] The array to be shuffled
  # @return [Array]
  def self.shuffle_a(arr)
    len = arr.length
    max = len - 1
    cyc = [* (0..max) ]
    for d in cyc
      e = rand(d+1)
      next if e == d
      f = arr[d];
      g = arr[e];
      arr[d] = g;
      arr[e] = f;
    end
    return arr
  end

  # Permute the case of a word
  def self.permute_case(word, idx=0)
    res = []

    if( (UpperAlpha+LowerAlpha).index(word[idx,1]))

      word_ucase = word.dup
      word_ucase[idx, 1] = word[idx, 1].upcase

      word_lcase = word.dup
      word_lcase[idx, 1] = word[idx, 1].downcase

      if (idx == word.length)
        return [word]
      else
        res << permute_case(word_ucase, idx+1)
        res << permute_case(word_lcase, idx+1)
      end
    else
      res << permute_case(word, idx+1)
    end

    res.flatten
  end

  # Generate a random hostname
  #
  # @return [String] A random string conforming to the rules of FQDNs
  def self.rand_hostname
    host = []
    (rand(5) + 1).times {
      host.push(Rex::Text.rand_text_alphanumeric(rand(10) + 1))
    }
    d = ['com', 'net', 'org', 'gov']
    host.push(d[rand(d.size)])
    host.join('.').downcase
  end

  # Generate a state
  def self.rand_state()
    States[rand(States.size)]
  end


  #
  # Calculate the ROR13 hash of a given string
  #
  # @return [Fixnum]
  def self.ror13_hash(name)
    hash = 0
    name.unpack("C*").each {|c| hash = ror(hash, 13); hash += c }
    hash
  end

  #
  # Rotate a 32-bit value to the right by +cnt+ bits
  #
  # @param val [Fixnum] The value to rotate
  # @param cnt [Fixnum] Number of bits to rotate by
  def self.ror(val, cnt)
    bits = [val].pack("N").unpack("B32")[0].split(//)
    1.upto(cnt) do |c|
      bits.unshift( bits.pop )
    end
    [bits.join].pack("B32").unpack("N")[0]
  end

  #
  # Rotate a 32-bit value to the left by +cnt+ bits
  #
  # @param val (see ror)
  # @param cnt (see ror)
  # @return (see ror)
  def self.rol(val, cnt)
    bits = [val].pack("N").unpack("B32")[0].split(//)
    1.upto(cnt) do |c|
      bits.push( bits.shift )
    end
    [bits.join].pack("B32").unpack("N")[0]
  end

  #
  # Split a string by n character into an array
  #
  def self.split_to_a(str, n)
    if n > 0
      s = str.dup
      until s.empty?
        (ret ||= []).push s.slice!(0, n)
      end
    else
      ret = str
    end
    ret
  end

  #
  # Pack a value as 64 bit litle endian; does not exist for Array.pack
  #
  def self.pack_int64le(val)
    [val & 0x00000000ffffffff, val >> 32].pack("V2")
  end


  #
  # A custom unicode filter for dealing with multi-byte strings on a 8-bit console
  # Punycode would have been more "standard", but it requires valid Unicode chars
  #
  def self.unicode_filter_encode(str)
    if (str.to_s.unpack("C*") & ( LowAscii + HighAscii + "\x7f" ).unpack("C*")).length > 0
      str = "$U$" + str.unpack("C*").select{|c| c < 0x7f and c > 0x1f and c != 0x2d}.pack("C*") + "-0x" + str.unpack("H*")[0]
    else
      str
    end
  end

  def self.unicode_filter_decode(str)
    str.to_s.gsub( /\$U\$([\x20-\x2c\x2e-\x7E]*)\-0x([A-Fa-f0-9]+)/n ){|m| [$2].pack("H*") }
  end

protected

  def self.converge_sets(sets, idx, offsets, length) # :nodoc:
    buf = sets[idx][offsets[idx]].chr

    # If there are more sets after use, converage with them.
    if (sets[idx + 1])
      buf << converge_sets(sets, idx + 1, offsets, length)
    else
      # Increment the current set offset as well as previous ones if we
      # wrap back to zero.
      while (idx >= 0 and ((offsets[idx] = (offsets[idx] + 1) % sets[idx].length)) == 0)
        idx -= 1
      end

      # If we reached the point where the idx fell below zero, then that
      # means we've reached the maximum threshold for permutations.
      if (idx < 0)
        return buf
      end

    end

    buf
  end

  def self.load_codepage()
    return if (!@@codepage_map_cache.nil?)
    file = File.join(File.dirname(__FILE__),'codepage.map')
    page = ''
    name = ''
    map = {}
    File.open(file).each { |line|
      next if line =~ /^#/
      next if line =~ /^\s*$/
      data = line.split
      if data[1] =~ /^\(/
        page = data.shift.to_i
        name = data.join(' ').sub(/^\(/,'').sub(/\)$/,'')
        map[page] = {}
        map[page]['name'] = name
        map[page]['data'] = {}
      else
        data.each { |entry|
          wide, char = entry.split(':')
          char = [char].pack('H*')
          wide = [wide].pack('H*')
          if map[page]['data'][char].nil?
            map[page]['data'][char] = [wide]
          else
            map[page]['data'][char].push(wide)
          end
        }
      end
    }
    @@codepage_map_cache = map
  end

  # @param str [String] Data to checksum
  # @return [Fixnum] 8-bit checksum
  def self.checksum8(str)
    (str.unpack("C*").inject(:+) || 0) % 0x100
  end

  # @param str [String] Little-endian data to checksum
  # @return [Fixnum] 16-bit checksum
  def self.checksum16_le(str)
    (str.unpack("v*").inject(:+) || 0) % 0x10000
  end

  # @param str [String] Big-endian data to checksum
  # @return [Fixnum] 16-bit checksum
  def self.checksum16_be(str)
    (str.unpack("n*").inject(:+) || 0) % 0x10000
  end

  # @param str [String] Little-endian data to checksum
  # @return [Fixnum] 32-bit checksum
  def self.checksum32_le(str)
    (str.unpack("V*").inject(:+) || 0) % 0x100000000
  end

  # @param str [String] Big-endian data to checksum
  # @return [Fixnum] 32-bit checksum
  def self.checksum32_be(str)
    (str.unpack("N*").inject(:+) || 0) % 0x100000000
  end

end
end

