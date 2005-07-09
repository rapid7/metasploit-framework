#!/usr/bin/ruby

require 'rex/encoder/xor'
require 'rex/encoding/xor/d_word'

class Rex::Encoder::Xor::DWord < Rex::Encoder::Xor
	EncoderKlass = Rex::Encoding::Xor::DWord
end
