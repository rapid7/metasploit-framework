#!/usr/bin/ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'rex/encoding/xor/d_word_additive'
require 'rex/encoding/xor/byte.rb.ut'

module Rex::Encoding::Xor
class DWordAdditive::UnitTest < Byte::UnitTest

	def enc
		DWordAdditive
	end
end
end
