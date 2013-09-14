#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/encoder/xor'
require 'rex/encoding/xor/dword'

###
#
# This class wraps the Dword XOR encoder.
#
###
class Rex::Encoder::Xor::Dword < Rex::Encoder::Xor
  EncoderKlass = Rex::Encoding::Xor::Dword
end
