#!/usr/bin/ruby

require 'Rex/Encoder/Xor'
require 'Rex/Encoding/Xor/DWordAdditive'

class Rex::Encoder::Xor::DWordAdditive < Rex::Encoder::Xor
	EncoderKlass = Rex::Encoding::Xor::DWordAdditive
end
