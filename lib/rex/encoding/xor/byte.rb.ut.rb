#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'rex/encoding/xor/byte'
require 'rex/encoding/xor/generic.rb.ut'

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