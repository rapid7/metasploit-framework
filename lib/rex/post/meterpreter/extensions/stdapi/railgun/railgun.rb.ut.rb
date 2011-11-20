#!/usr/bin/env ruby

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

	# DLLs we know should be available at the time of this writing,
	# and DLLs that because of changes since then should be available
	STOCK_DLLS = [
		'kernel32',
		'ntdll',
		'user32',
		'ws2_32',
		'iphlpapi',
		'advapi32',
		'shell32',
		'netapi32',
		'crypt32',
	] | Railgun::BUILTIN_DLLS

	include MockMagic

	def test_known_dll_names
		railgun = Railgun.new(make_mock_client())

		dll_names = railgun.known_dll_names

		assert_equal(dll_names.length, dll_names.uniq.length,
			"known_dll_names should not have duplicates")

		STOCK_DLLS.each do |name|
			assert(dll_names.include?(name),
				"known_dll_names should include #{name}")
		end
	end
#
# TODO:
#	def test_multi
#		mock_function_descriptions.each do |func|
#			railgun = Railgun.new(make_mock_client(func[:platform]))
#
#			functions = [
#				[func[:dll_name], func[:name], func[:ruby_args]]
#			]
#
#			results = railgun.multi(functions)
#		end
#	end
#
	def test_const
		railgun = Railgun.new(make_mock_client())

		assert_equal(0, railgun.const('SUCCESS'),
			"const should look up constants like SUCCESS")
	end

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

		wrapper = railgun.send(target_dll_name.to_sym)

		assert_same(wrapper._dll, actual_dll,
			"railgun instance responds with dll wrapper of requested dll")
	end

	def test_method_missing
		railgun = Railgun.new(make_mock_client())

		STOCK_DLLS.each do |dll_name|
			assert_nothing_raised do
				railgun.send(dll_name.to_sym)
			end
		end
	end

	def test_get_dll
		railgun = Railgun.new(make_mock_client())

		STOCK_DLLS.each do |dll_name|
			dll = railgun.get_dll(dll_name)

			# We want to ensure autoloading is working
			assert(dll.instance_of?(DLL),
				"get_dll should be able to return a value for dll #{dll_name}")

			assert(dll.frozen?,
				"Stock DLLs loaded lazily in get_dll should be frozen")

			# adding a function should create a local unfrozen instance
			railgun.add_function(dll_name, '__lolz', 'VOID', [])

			unfrozen_dll = railgun.get_dll(dll_name)

			assert_not_same(dll, unfrozen_dll,
				"add_function should create a local unfrozen instance that get_dll can then access")

			assert(!unfrozen_dll.frozen?,
				"add_function should create a local unfrozen instance that get_dll can then access")
		end
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
