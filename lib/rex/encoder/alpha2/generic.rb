#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/text'

module Rex
module Encoder
module Alpha2

class Generic

  # Note: 'A' is presumed to be accepted, but excluded from the accepted characters, because it serves as the terminator
  def Generic.default_accepted_chars ; ('a' .. 'z').to_a + ('B' .. 'Z').to_a + ('0' .. '9').to_a ; end

  def Generic.gen_decoder_prefix(reg, offset)
    # Should never happen - have to pick a specifc
    # encoding:
    # alphamixed, alphaupper, unicodemixed, unicodeupper
    ''
  end

  def Generic.gen_decoder(reg, offset)
    # same as above
    return ''
  end

  def Generic.gen_second(block, base)
    # XOR encoder for ascii - unicode uses additive
    (block^base)
  end

  def Generic.encode_byte(block, badchars)
    accepted_chars = default_accepted_chars.dup

    badchars.each_char {|c| accepted_chars.delete(c) } if badchars

    # No, not nipple.
    nibble_chars = Array.new(0x10) {[]}
    accepted_chars.each {|c| nibble_chars[c.unpack('C')[0] & 0x0F].push(c) }

    poss_encodings = []

    block_low_nibble = block & 0x0F
    block_high_nibble = block >> 4

    # Get list of chars suitable for expressing lower part of byte
    first_chars = nibble_chars[block_low_nibble]

    # Build a list of possible encodings
    first_chars.each do |first_char|
      first_high_nibble = first_char.unpack('C')[0] >> 4

      # In the decoding process, the low nibble of the second char gets combined
      # (either ADDed or XORed depending on the encoder) with the high nibble of the first char,
      # and we want the high nibble of our input byte to result
      second_low_nibble = gen_second(block_high_nibble, first_high_nibble) & 0x0F

      # Find valid second chars for this first char and add each combination to our possible encodings
      second_chars = nibble_chars[second_low_nibble]
      second_chars.each {|second_char| poss_encodings.push(second_char + first_char) }
    end

    if poss_encodings.empty?
      raise RuntimeError, "No encoding of #{"0x%.2X" % block} possible with limited character set"
    end

    # Return a random encoding
    poss_encodings[rand(poss_encodings.length)]
  end

  def Generic.encode(buf, reg, offset, badchars = '')
    encoded = gen_decoder(reg, offset)

    buf.each_byte {
      |block|

      encoded << encode_byte(block, badchars)
    }

    encoded << add_terminator()

    return encoded
  end

  # 'A' signifies the end of the encoded shellcode
  def Generic.add_terminator()
    'AA'
  end

end end end end

