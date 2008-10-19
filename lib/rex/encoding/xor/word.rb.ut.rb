#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'rex/encoding/xor/word'
require 'rex/encoding/xor/byte.rb.ut'

class Rex::Encoding::Xor::Word::UnitTest < Rex::Encoding::Xor::Byte::UnitTest

	def enc
		Rex::Encoding::Xor::Word
	end
end