#!/usr/bin/ruby

$:.unshift(File.join('..', '..', '..', File.dirname(__FILE__)))

require 'Rex/Encoding/Xor/Word'
require 'Rex/Encoding/Xor/Byte.rb.ut'

class Rex::Encoding::Xor::Word::UnitTest < Rex::Encoding::Xor::Byte::UnitTest

	def enc
		Rex::Encoding::Xor::Word
	end
end
