# -*- coding: binary -*-
module Rex
  module Text
    # We are re-opening the module to add these module methods.
    # Breaking them up this way allows us to maintain a little higher
    # degree of organisation and make it easier to find what you're looking for
    # without hanging the underlying calls that we historically rely upon.

    #
    # Creates a comma separated list of numbers
    #
    def self.to_num(str, wrap = DefaultWrap)
      code = str.unpack('C*')
      buff = ""
      0.upto(code.length-1) do |byte|
        if(byte % 15 == 0) and (buff.length > 0)
          buff << "\r\n"
        end
        buff << sprintf('0x%.2x, ', code[byte])
      end
      # strip , at the end
      buff = buff.chomp(', ')
      buff << "\r\n"
      return buff
    end

    #
    # Creates a comma separated list of dwords
    #
    def self.to_dword(str, wrap = DefaultWrap)
      code = str
      alignnr = str.length % 4
      if (alignnr > 0)
        code << "\x00" * (4 - alignnr)
      end
      codevalues = Array.new
      code.split("").each_slice(4) do |chars4|
        chars4 = chars4.join("")
        dwordvalue = chars4.unpack('*V')
        codevalues.push(dwordvalue[0])
      end
      buff = ""
      0.upto(codevalues.length-1) do |byte|
        if(byte % 8 == 0) and (buff.length > 0)
          buff << "\r\n"
        end
        buff << sprintf('0x%.8x, ', codevalues[byte])
      end
      # strip , at the end
      buff = buff.chomp(', ')
      buff << "\r\n"
      return buff
    end

    #
    # Returns the words in +str+ as an Array.
    #
    # strict - include *only* words, no boundary characters (like spaces, etc.)
    #
    def self.to_words( str, strict = false )
      strict ? str.scan(/\w+/) : str.split(/\b/)
    end

    #
    # Pack a value as 64 bit litle endian; does not exist for Array.pack
    #
    def self.pack_int64le(val)
      [val & 0x00000000ffffffff, val >> 32].pack("V2")
    end

    #
    # Rotate a 32-bit value to the right by +cnt+ bits
    #
    # @param val [Integer] The value to rotate
    # @param cnt [Integer] Number of bits to rotate by
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

  end
end
