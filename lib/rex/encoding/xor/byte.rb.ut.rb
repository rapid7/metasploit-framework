#!/usr/bin/ruby

$:.unshift(File.join('..', '..', '..', File.dirname(__FILE__)))

require 'Rex/Encoding/Xor/Byte'
require 'Rex/Encoding/Xor/Generic.ut'
require 'test/unit'
require 'test/unit/ui/console/testrunner'

#
# I suck because I want to inherit a test case, but this will
# also cause it to run the test case I'm inheriting, so this runs both the
# Byte and Generic tests, oh well for now...
#

class Rex::Encoding::Xor::Byte::UnitTest < Rex::Encoding::Xor::Generic::UnitTest

	def enc
		Rex::Encoding::Xor::Byte
	end

	def hook_static_encode(data, key, expected)
		if key.length != enc.keysize
			assert_raise(ArgumentError) { enc.encode(data, key) }
		else
			enc.encode(data, key)
		end
	end
end
