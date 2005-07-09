#!/usr/bin/ruby

require 'rex/encoder/xor'
require 'rex/encoding/xor/dword_additive'

class Rex::Encoder::Xor::DwordAdditive < Rex::Encoder::Xor
	EncoderKlass = Rex::Encoding::Xor::DwordAdditive
end
