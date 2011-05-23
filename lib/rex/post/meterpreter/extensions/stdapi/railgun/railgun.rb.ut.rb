#!/usr/bin/env rubyj

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..','..','..','..','..', 'lib')) 

require 'rex/post/meterpreter/extensions/stdapi/railgun/railgun'
require 'rex/post/meterpreter/extensions/stdapi/railgun/mock_magic'
require 'test/unit'
require 'benchmark'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
class Railgun::UnitTest < Test::Unit::TestCase

	include MockMagic

	def test_add_dll
		railgun = Railgun.new(make_mock_client())

		target_dll_name = 'discordia'
		target_windows_name = 'C:\look\behind\you'

		railgun.add_dll(target_dll_name, target_windows_name)

		actual_dll = railgun.get_dll(target_dll_name);

		assert_not_nil(actual_dll,
			"add_dll should make a DLL accessible via get_dll")

		assert_equal(actual_dll.dll_path, target_windows_name,
			"add_dll should set a dll path when specified")

# 
#		wrapper = railgun.send(target_dll_name.to_sym)
#
#		assert_same(wrapper._dll, actual_dll,
#			"railgun instance responds with dll wrapper as expected")
	end

	def test_add_function
		mock_function_descriptions.each do |func|
			railgun = Railgun.new(make_mock_client(func[:platform]))

			dll_name = func[:dll_name]
			function_name = func[:name]
			
			railgun.add_dll(dll_name)
			railgun.add_function(dll_name, function_name, func[:return_type], func[:params])

			assert(railgun.get_dll(dll_name).functions.has_key?(function_name),
				"add_function should add a function to the DLL specified")
		end
	end
end
end
end
end
end
end
end
