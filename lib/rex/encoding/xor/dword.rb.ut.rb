#!/usr/bin/ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'Rex/Encoding/Xor/DWord'
require 'Rex/Encoding/Xor/Byte.rb.ut'

module Rex::Encoding::Xor
class DWord::UnitTest < Byte::UnitTest

	def enc
		DWord
	end
end
end
