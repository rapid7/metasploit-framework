# -*- coding: binary -*-
require 'rex/text/version'
require 'digest/md5'
require 'digest/sha1'
require 'stringio'
require 'cgi'
require 'zlib'
require 'openssl'

require 'rex/text/illegal_sequence'
require 'rex/text/rand'
require 'rex/text/checksum'
require 'rex/text/hash'
require 'rex/text/lang'
require 'rex/text/hex'
require 'rex/text/base32'
require 'rex/text/base64'
require 'rex/text/unicode'
require 'rex/text/binary_manipulation'
require 'rex/text/randomize'
require 'rex/text/compress'
require 'rex/text/silly'
require 'rex/text/encode'
require 'rex/text/block_api'
require 'rex/text/ebcdic'
require 'rex/text/pattern'
require 'rex/text/badchars'
require 'rex/text/xor'

require 'rex/text/color'
require 'rex/text/table'


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

    UpperAlpha   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    LowerAlpha   = "abcdefghijklmnopqrstuvwxyz"
    Numerals     = "0123456789"
    Base32       = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    Base64       = UpperAlpha + LowerAlpha + Numerals + '+/'
    Base64Url    = UpperAlpha + LowerAlpha + Numerals + '-_'
    Alpha        = UpperAlpha + LowerAlpha
    AlphaNumeric = Alpha + Numerals
    HighAscii    = [*(0x80 .. 0xff)].pack("C*")
    LowAscii     = [*(0x00 .. 0x1f)].pack("C*")
    DefaultWrap  = 60
    AllChars     = [*(0x00 .. 0xff)].pack("C*")
    Punctuation  = ( [*(0x21 .. 0x2f)] + [*(0x3a .. 0x3F)] + [*(0x5b .. 0x60)] + [*(0x7b .. 0x7e)] ).flatten.pack("C*")

    DefaultPatternSets = [ Rex::Text::UpperAlpha, Rex::Text::LowerAlpha, Rex::Text::Numerals ]

    #
    # Returns the raw string
    #
    def self.to_raw(str)
      return str
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
    # Wraps text at a given column using a supplied indention
    #
    def self.wordwrap(str, indent = 0, col = DefaultWrap, append = '', prepend = '')
      return str.gsub(/.{1,#{col - indent}}(?:\s|\Z)/){
        ( (" " * indent) + prepend + $& + append + 5.chr).gsub(/\n\005/,"\n").gsub(/\005/,"\n")}
    end


    #
    # Convert 16-byte string to a GUID string
    #
    # @example
    #   str = "ABCDEFGHIJKLMNOP"
    #   Rex::Text.to_guid(str) #=> "{44434241-4645-4847-494a-4b4c4d4e4f50}"
    #
    # @param bytes [String] 16 bytes which represent a GUID in the proper
    #   order.
    #
    # @return [String]
    def self.to_guid(bytes)
      return nil unless bytes
      s = bytes.unpack('H*')[0]
      parts = [
        s[6,  2] + s[4,  2] + s[2, 2] + s[0, 2],
        s[10, 2] + s[8,  2],
        s[14, 2] + s[12, 2],
        s[16, 4],
        s[20, 12]
      ]
      "{#{parts.join('-')}}"
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

    protected

    def self.converge_sets(sets, idx, offsets, length) # :nodoc:
      buf = sets[idx][offsets[idx]].chr

      # If there are more sets after use, converge with them.
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



  end
end
