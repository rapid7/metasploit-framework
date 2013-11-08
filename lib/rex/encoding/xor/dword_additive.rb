#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/encoding/xor/exceptions'
require 'rex/encoding/xor/generic'

#
# Routine for xor encoding a buffer by a 2-byte (intel word) key.  The perl
# version used to pad this buffer out to a 2-byte boundary, but I can't think
# of a good reason to do that anymore, so this doesn't.
#

module Rex
module Encoding
module Xor

class DwordAdditive < Generic

  def DwordAdditive.keysize
    4
  end

  def DwordAdditive._packspec
    'V'
  end

  def DwordAdditive.pack_key(key)
    return [ key ].pack(_packspec)
  end
  def DwordAdditive.unpack_key(key)
    return key.unpack(_packspec)[0]
  end

  # hook in the key mutation routine of encode for the additive feedback
  def DwordAdditive._encode_mutate_key(buf, key, pos, len)
    if (pos + 1) % len == 0
      # add the last len bytes (in this case 4) with the key,
      # dropping off any overflow
      key = pack_key(
        unpack_key(key) + unpack_key(buf[pos - (len - 1), len]) &
          (1 << (len << 3)) - 1
      )
    end

    return key
  end

  #
  # I realize this algorithm is broken.  We invalidate some keys
  # in _find_bad_keys that could actually be perfectly fine.  However,
  # it seems to work ok for now, and this is all just a lame adhoc method.
  # Maybe someday we can revisit this and make it a bit less ghetto...
  #

  def DwordAdditive._find_good_key(data, badkeys, badchars)

    ksize  = keysize
    kstart = ""
    ksize.times { kstart << rand(256) } # random key starting place

    key = kstart.dup

    #
    # now for the ghettoness of an algorithm:
    #  try the random key we picked
    #  if the key failed, figure out which key byte corresponds
    #  increment that key byte
    #  if we wrapped a byte all the way around, fail :(
    #

    loop do
      # ok, try to encode it, any bad chars present?
      pos = _check(data, key, badchars)

      # yay, no problems, we found a key!
      break if !pos

      strip = pos % ksize

      # increment the offending key byte
      key[strip] = key[strip] + 1 & 0xff

      # We wrapped around!
      if key[strip] == kstart[strip]
        raise KeySearchError, "Key space exhausted on strip #{strip}!", caller
      end
    end

    return key
  end

end end end end # DwordAdditive/Xor/Encoding/Rex

