#!/usr/bin/ruby

require 'rex/encoder/xor'
require 'rex/encoding/xor/dword'

class Rex::Encoder::Xor::Dword < Rex::Encoder::Xor
	EncoderKlass = Rex::Encoding::Xor::Dword
end
