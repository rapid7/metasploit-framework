#!/usr/bin/ruby

$:.unshift(File.join('..', '..', '..', File.dirname(__FILE__)))

require 'Rex/Encoding/Xor/DWordAdditive'
require 'Rex/Encoding/Xor/Byte.rb.ut'

module Rex::Encoding::Xor
class DWordAdditive::UnitTest < Byte::UnitTest

	def enc
		DWordAdditive
	end
end
end
