#!/usr/bin/ruby

require 'rex/encoder/xor'
require 'rex/encoding/xor/d_word_additive'

class Rex::Encoder::Xor::DWordAdditive < Rex::Encoder::Xor
	EncoderKlass = Rex::Encoding::Xor::DWordAdditive
end
