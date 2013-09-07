#!/usr/bin/env ruby
# -*- coding: binary -*-

module Rex
module Encoder

###
#
# This class performs basic XOR encoding.
#
###
class Xor

  attr_accessor :raw, :encoded, :badchars, :opts, :key, :fkey # :nodoc:

  #
  # wrap that in a wanna be static class
  #
  def self.encode(*args)
    self.new.encode(*args)
  end

  #
  # Return the class associated with this encoder.
  #
  def encoder()
    self.class::EncoderKlass
  end

  #
  # This method encodes the supplied data, taking into account the badchar
  # list, and returns the encoded buffer.
  #
  def encode(data, badchars = '', opts = { })
    self.raw      = data
    self.badchars = badchars
    self.opts     = opts

    # apply any transforms to the plaintext data
    data = _unencoded_transform(data)

    self.encoded, self.key, self.fkey = encoder().find_key_and_encode(data, badchars)

    # apply any transforms to the encoded data
    self.encoded = _encoded_transform(encoded)

    return _prepend() + encoded + _append()
  end

  protected
  def _unencoded_transform(data) # :nodoc:
    data
  end

  def _encoded_transform(data) # :nodoc:
    data
  end

  def _prepend() # :nodoc:
    ""
  end

  def _append() # :nodoc:
    ""
  end

end

end end

