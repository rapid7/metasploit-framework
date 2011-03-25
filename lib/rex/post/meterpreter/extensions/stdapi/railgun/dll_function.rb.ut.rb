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

	VALID_RETURN_TYPE = ''
	INVALID_RETURN_TYPE = 'INVALID_RETURN_TYPE'

	VALID_DIRECTION = 'out'
	INVALID_DIRECTION = 'invalid'

	def test_initialize
		
	end

	def test_check_type_exists
		
	end

	def test_check_return_type
	end

	def test_check_params
	end
end
end
end
end
end
end
end
