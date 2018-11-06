# encoding: utf-8


#
# Ascii85 is an implementation of Adobe's binary-to-text encoding of the
# same name in pure Ruby.
#
# See http://www.adobe.com/products/postscript/pdfs/PLRM.pdf page 131
# and http://en.wikipedia.org/wiki/Ascii85 for more information about
# the format.
#
# Author::  Johannes Holzfuß (johannes@holzfuss.name)
# License:: Distributed under the MIT License (see LICENSE file)
#


module Ascii85

  #
  # Encodes the bytes of the given String as Ascii85.
  #
  # If +wrap_lines+ evaluates to +false+, the output will be returned as
  # a single long line. Otherwise #encode formats the output into lines
  # of length +wrap_lines+ (minimum is 2).
  #
  #     Ascii85.encode("Ruby")
  #     => <~;KZGo~>
  #
  #     Ascii85.encode("Supercalifragilisticexpialidocious", 15)
  #     => <~;g!%jEarNoBkD
  #        BoB5)0rF*),+AU&
  #        0.@;KXgDe!L"F`R
  #        ~>
  #
  #     Ascii85.encode("Supercalifragilisticexpialidocious", false)
  #     => <~;g!%jEarNoBkDBoB5)0rF*),+AU&0.@;KXgDe!L"F`R~>
  #
  #
  def self.encode(str, wrap_lines = 80)

    to_encode = str.to_s
    return '' if to_encode.empty?

    # Deal with multi-byte encodings
    if to_encode.respond_to?(:bytesize)
      input_size = to_encode.bytesize
    else
      input_size = to_encode.size
    end

    # Compute number of \0s to pad the message with (0..3)
    padding_length = (-input_size) % 4

    # Extract big-endian integers
    tuples = (to_encode + ("\0" * padding_length)).unpack('N*')

    # Encode
    tuples.map! do |tuple|
      if tuple == 0
        'z'
      else
        tmp = ""
        5.times do
          tmp << ((tuple % 85) + 33).chr
          tuple /= 85
        end
        tmp.reverse
      end
    end

    # We can't use the z-abbreviation if we're going to cut off padding
    if (padding_length > 0) and (tuples.last == 'z')
      tuples[-1] = '!!!!!'
    end

    # Cut off the padding
    tuples[-1] = tuples[-1][0..(4 - padding_length)]

    # If we don't need to wrap the lines, add delimiters and return
    if (!wrap_lines)
      return '<~' + tuples.join + '~>'
    end

    # Otherwise we wrap the lines

    line_length = [2, wrap_lines.to_i].max

    wrapped = []
    to_wrap = '<~' + tuples.join

    0.step(to_wrap.length, line_length) do |index|
      wrapped << to_wrap.slice(index, line_length)
    end

    # Add end-marker – on a new line if necessary
    if (wrapped.last.length + 2) > line_length
      wrapped << '~>'
    else
      wrapped[-1] << '~>'
    end

    return wrapped.join("\n")
  end

  #
  # Searches through +str+ and decodes the _first_ Ascii85-String found.
  #
  # #decode expects an Ascii85-encoded String enclosed in <~ and ~> — it will
  # ignore all characters outside these markers. The returned strings are always
  # encoded as ASCII-8BIT.
  #
  #     Ascii85.decode("<~;KZGo~>")
  #     => "Ruby"
  #
  #     Ascii85.decode("Foo<~;KZGo~>Bar<~;KZGo~>Baz")
  #     => "Ruby"
  #
  #     Ascii85.decode("No markers")
  #     => ""
  #
  # #decode will raise Ascii85::DecodingError when malformed input is
  # encountered.
  #
  def self.decode(str)

    input = str.to_s

    opening_delim = '<~'
    closing_delim = '~>'

    # Make sure the delimiter strings have the correct encoding.
    #
    # Although I don't think it likely, this may raise encoding
    # errors if an especially exotic input encoding is introduced.
    # As of Ruby 1.9.2 all non-dummy encodings work fine though.
    #
    if opening_delim.respond_to?(:encode!)
      opening_delim.encode!(input.encoding)
      closing_delim.encode!(input.encoding)
    end

    # Get the positions of the opening/closing delimiters. If there is
    # no pair of opening/closing delimiters, return the empty string.
    (start_pos = input.index(opening_delim))                or return ''
    (end_pos   = input.index(closing_delim, start_pos + 2)) or return ''

    # Get the string inside the delimiter-pair
    input = input[(start_pos + 2)...end_pos]

    # Decode
    word   = 0
    count  = 0
    result = []

    input.each_byte do |c|

      case c.chr
      when " ", "\t", "\r", "\n", "\f", "\0"
        # Ignore whitespace
        next

      when 'z'
        if count == 0
          # Expand z to 0-word
          result << 0
        else
          raise(Ascii85::DecodingError, "Found 'z' inside Ascii85 5-tuple")
        end

      when '!'..'u'
        # Decode 5 characters into a 4-byte word
        word  += (c - 33) * 85**(4 - count)
        count += 1

        if count == 5

          if word > 0xffffffff
            raise(Ascii85::DecodingError,
                  "Invalid Ascii85 5-tuple (#{word} >= 2**32)")
          end

          result << word

          word  = 0
          count = 0
        end

      else
        raise(Ascii85::DecodingError,
              "Illegal character inside Ascii85: #{c.chr.dump}")
      end

    end

    # Convert result into a String
    result = result.pack('N*')

    if count > 0
      # Finish last, partially decoded 32-bit-word

      if count == 1
        raise(Ascii85::DecodingError,
              "Last 5-tuple consists of single character")
      end

      count -= 1
      word  += 85**(4 - count)

      result << ((word >> 24) & 255).chr if count >= 1
      result << ((word >> 16) & 255).chr if count >= 2
      result << ((word >>  8) & 255).chr if count == 3
    end

    return result
  end

  #
  # This error is raised when Ascii85.decode encounters one of the following
  # problems in the input:
  #
  # * An invalid character. Valid characters are '!'..'u' and 'z'.
  # * A 'z' character inside a 5-tuple. 'z's are only valid on their own.
  # * An invalid 5-tuple that decodes to >= 2**32
  # * The last tuple consisting of a single character. Valid tuples always have
  #   at least two characters.
  #
  class DecodingError < StandardError; end

end
