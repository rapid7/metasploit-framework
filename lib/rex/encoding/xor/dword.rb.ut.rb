#!/usr/bin/ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'rex/encoding/xor/d_word'
require 'rex/encoding/xor/byte.rb.ut'

module Rex::Encoding::Xor
class DWord::UnitTest < Byte::UnitTest

	def enc
		DWord
	end
end
end
