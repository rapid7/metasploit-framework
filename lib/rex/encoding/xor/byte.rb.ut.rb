#!/usr/bin/ruby

$:.unshift(File.join('..', '..', '..', File.dirname(__FILE__)))

require 'Rex/Encoding/Xor/Byte'
require 'Rex/Encoding/Xor/Generic.rb.ut'

#
# I suck because I want to inherit a test case, but this will
# also cause it to run the test case I'm inheriting, so this runs both the
# Byte and Generic tests, oh well for now...
#

module Rex::Encoding::Xor
class Byte::UnitTest < Generic::UnitTest

	def enc
		Byte
	end
end
end
