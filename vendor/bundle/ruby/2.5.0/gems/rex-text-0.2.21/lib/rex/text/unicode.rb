# -*- coding: binary -*-
module Rex
  module Text
    # We are re-opening the module to add these module methods.
    # Breaking them up this way allows us to maintain a little higher
    # degree of organisation and make it easier to find what you're looking for
    # without hanging the underlying calls that we historically rely upon.

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

    # Converts US-ASCII to UTF-8, skipping over any characters which don't
    # convert cleanly. This is a convenience method that wraps
    # String#encode with non-raising default paramaters.
    #
    # @param str [String] An encodable ASCII string
    # @return [String] a UTF-8 equivalent
    # @note This method will discard invalid characters
    def self.to_utf8(str)
      str.encode('utf-8', { :invalid => :replace, :undef => :replace, :replace => '' })
    end

    #
    # Returns a unicode escaped string for Javascript
    #
    def self.to_unescape(data, endian=ENDIAN_LITTLE, prefix='%%u')
      data << "\x41" if (data.length % 2 != 0)
      dptr = 0
      buff = ''
      while (dptr < data.length)
        c1 = data[dptr,1].unpack("C*")[0]
        dptr += 1
        c2 = data[dptr,1].unpack("C*")[0]
        dptr += 1

        if (endian == ENDIAN_LITTLE)
          buff << sprintf("#{prefix}%.2x%.2x", c2, c1)
        else
          buff << sprintf("#{prefix}%.2x%.2x", c1, c2)
        end
      end
      return buff
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

  end
end

# from http://dzone.com/snippets/convert-unicode-codepoints-utf

# This module lazily defines constants of the form Uxxxx for all Unicode
# codepoints from U0000 to U10FFFF. The value of each constant is the
# UTF-8 string for the codepoint.
# Examples:
#   copyright = Unicode::U00A9
#   euro = Unicode::U20AC
#   infinity = Unicode::U221E
#
module ::Unicode
  def self.const_missing(name)
    # Check that the constant name is of the right form: U0000 to U10FFFF
    if name.to_s =~ /^U([0-9a-fA-F]{4,5}|10[0-9a-fA-F]{4})$/
      # Convert the codepoint to an immutable UTF-8 string,
      # define a real constant for that value and return the value
      #p name, name.class
      const_set(name, [$1.to_i(16)].pack("U").freeze)
    else  # Raise an error for constants that are not Unicode.
      raise NameError, "Uninitialized constant: Unicode::#{name}"
    end
  end
end
