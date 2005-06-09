#!/usr/bin/ruby

require 'Rex/Encoder/Xor'
require 'Rex/Encoding/Xor/DWord'

class Rex::Encoder::Xor::DWord < Rex::Encoder::Xor
	EncoderKlass = Rex::Encoding::Xor::DWord
end
