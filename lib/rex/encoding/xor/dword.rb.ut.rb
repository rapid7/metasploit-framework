#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'rex/encoding/xor/dword'
require 'rex/encoding/xor/byte.rb.ut'

module Rex::Encoding::Xor
class Dword::UnitTest < Byte::UnitTest

	def enc
		Dword
	end
end
end