#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..','..','..','..','..', 'lib')) 

require 'rex/post/meterpreter/extensions/stdapi/railgun/dll'
require 'rex/post/meterpreter/extensions/stdapi/railgun/mock_magic'
require 'test/unit'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
class DLL::UnitTest < Test::Unit::TestCase

	include MockMagic

	def test_add_function
		mock_function_descriptions.each do |func|
			dll = DLL.new(func[:dll_name], nil)
			dll.add_function(func[:name], func[:return_type], func[:params])

			assert(dll.functions.has_key?(func[:name]),
				"add_function should expand the list of available functions")
		end
	end

	def test_call_function
		mock_function_descriptions.each do |func|
			client = make_mock_client(func[:platform], func[:request_to_client], func[:response_from_client])
			dll = DLL.new(func[:dll_name], nil)

			dll.add_function(func[:name], func[:return_type], func[:params])

			actual_returned_hash = dll.call_function(func[:name].to_sym, func[:ruby_args], client)

			assert(func[:returned_hash].has_key?('GetLastError'),
				"process_function_call should add the result of GetLastError to the key GetLastError")

			assert_equal(func[:returned_hash], actual_returned_hash,
				"process_function_call convert function result to a ruby hash")
		end
	end
end
end
end
end
end
end
end
