module Rex
  module Text
    # We are re-opening the module to add these module methods.
    # Breaking them up this way allows us to maintain a little higher
    # degree of organisation and make it easier to find what you're looking for
    # without hanging the underlying calls that we historically rely upon.

    #
    # Returns the escaped hex version of the supplied string
    #
    # @example
    #   Rex::Text.to_hex("asdf") # => "\\x61\\x73\\x64\\x66"
    #
    # @param str (see to_octal)
    # @param prefix (see to_octal)
    # @param count [Integer] Number of bytes to put in each escape chunk
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
    # Converts a string to a nicely formatted hex dump
    #
    # @param str [String] The string to convert
    # @param width [Integer] Number of bytes to convert before adding a newline
    # @param base [Integer] The base address of the dump
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
      # This sanitization is terrible and breaks everything if it finds unicode.
      # ~4 Billion can't be wrong; long-term, this should be removed.
      if str.encoding == (::Encoding::UTF_8)
        return str
      end
      if whitespace
        str.gsub(/([\x00-\x20\x80-\xFF])/n){ |x| "\\x%.2x" % x.unpack("C*")[0] }
      else
        str.gsub(/([\x00-\x08\x0b\x0c\x0e-\x1f\x80-\xFF])/n){ |x| "\\x%.2x" % x.unpack("C*")[0]}
      end
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

  end
end
