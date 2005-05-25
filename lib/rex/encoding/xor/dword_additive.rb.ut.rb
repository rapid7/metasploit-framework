#!/usr/bin/ruby

$:.unshift(File.join('..', '..', '..', File.dirname(__FILE__)))

require 'Rex/Encoding/Xor/DWordAdditive'
require 'Rex/Encoding/Xor/Byte.rb.ut'

class Rex::Encoding::Xor::DWordAdditive::UnitTest < Rex::Encoding::Xor::Byte::UnitTest

	def enc
		Rex::Encoding::Xor::DWordAdditive
	end
end
