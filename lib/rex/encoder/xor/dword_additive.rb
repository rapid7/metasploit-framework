# -*- coding: binary -*-

require 'rex/encoder/xor'
require 'rex/encoding/xor/dword_additive'

###
#
# This class wraps the Dword XOR Additive feedback encoder.
#
###
class Rex::Encoder::Xor::DwordAdditive < Rex::Encoder::Xor
  EncoderKlass = Rex::Encoding::Xor::DwordAdditive
end
