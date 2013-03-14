#!/usr/bin/env ruby
# -*- coding: binary -*-

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..','..','..','..','..', 'lib'))

require 'rex/post/meterpreter/extensions/stdapi/railgun/dll'
require 'rex/post/meterpreter/extensions/stdapi/railgun/dll_wrapper'
require 'rex/post/meterpreter/extensions/stdapi/railgun/mock_magic'
require 'test/unit'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
class DLLWrapper::UnitTest < Test::Unit::TestCase

	include MockMagic

	def test_functions
		mock_function_descriptions.each do |func|
			client = make_mock_client(func[:platform], func[:request_to_client], func[:response_from_client])
			dll = DLL.new(func[:dll_name], client)

			dll_wrapper = DLLWrapper.new(dll, client)

			# This represents how people check if a function doesn't exist
			assert(!dll_wrapper.functions[func[:name]], 'Function non-existence can be chucked via .functions')

			dll.add_function(func[:name], func[:return_type], func[:params])

			# This represents how people check if a function exist
			assert(dll_wrapper.functions[func[:name]], 'Function existence can be chucked via .functions')

			actual_returned_hash = dll_wrapper.send(:method_missing, func[:name].to_sym, *func[:ruby_args])

			assert_equal(func[:returned_hash], actual_returned_hash,
				"method_missing should result in a successful call to specified function")
		end
	end

	def test_method_missing
		mock_function_descriptions.each do |func|
			client = make_mock_client(func[:platform], func[:request_to_client], func[:response_from_client])
			dll = DLL.new(func[:dll_name], client)

			dll.add_function(func[:name], func[:return_type], func[:params])

			dll_wrapper = DLLWrapper.new(dll, client)

			actual_returned_hash = dll_wrapper.send(:method_missing, func[:name].to_sym, *func[:ruby_args])

			assert_equal(func[:returned_hash], actual_returned_hash,
				"method_missing should result in a successful call to specified function")
		end
	end
end
end
end
end
end
end
end
