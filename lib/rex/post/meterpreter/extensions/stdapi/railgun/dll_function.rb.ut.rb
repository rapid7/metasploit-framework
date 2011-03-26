#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..','..','..','..','..', 'lib')) 

require 'rex/post/meterpreter/extensions/stdapi/railgun/dll_function'
require 'test/unit'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
class DLLFunction::UnitTest < Test::Unit::TestCase

	VALID_RETURN_TYPE = 'DWORD'
	NON_RETURN_DATATYPE = 'INVALID_RETURN_TYPE'

	VALID_DIRECTION = 'out'
	UNKNOWN_DIRECTION = 'unknown'

	VALID_DATATYPE = 'PBLOB'
	UNKNOWN_DATATYPE = 'UNKNOWN_DATATYPE'

	def test_initialize
		# TODO: haven't gotten around to writing this yet. Feel free to
#		skip("incomplete test coverage")
#
#		assert_nothing_raised("valid initialization should not raise") do
#		end
#
#		assert_raised(ArgumentError, "check_type_exists should raise ArgumentError on unknown datatypes") do
#		end
	
	end
end
end
end
end
end
end
end
