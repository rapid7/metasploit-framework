#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..','..','..','..','..', 'lib'))

require 'rex/post/meterpreter/extensions/stdapi/railgun/dll_helper'
require 'rex/post/meterpreter/extensions/stdapi/railgun/win_const_manager'
require 'rex/text'
require 'test/unit'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
class DLLHelper::UnitTest < Test::Unit::TestCase

	###
	# We will test against this instance of DLLHelper (a module) 
	# 
	# We freeze the instance and make the reference constant to ensure consistency
	##
	TEST_DLL_HELPER = Object.new.extend(DLLHelper).freeze

	def test_str_to_ascii_z
		original_string = '23 Skidoo!'

		# converts ruby string to zero-terminated ASCII string
		zero_terminated_ascii_attempt = TEST_DLL_HELPER.str_to_ascii_z(original_string)

		assert(zero_terminated_ascii_attempt  =~ /\x00$/, 
			"str_to_ascii_z should result in a 0 terminated string")

		assert(zero_terminated_ascii_attempt =~ /^#{original_string}/, 
			"str_to_ascii_z should still start with original string")

		assert_equal(original_string.length + 1, zero_terminated_ascii_attempt.length, 
			"str_to_ascii_z should have length of original pluss room for a terminal 0")
	end

	def test_asciiz_to_str
		target_string = '23 Skidoo!'
		post_zero_noise = 'Loud noises!'
		zero_terminated_string = target_string + "\x00" + post_zero_noise

		actual_string =  TEST_DLL_HELPER.asciiz_to_str(zero_terminated_string)

		assert(actual_string =~ /^#{target_string}/,
			"asciiz_to_str should preserve string before zero")

		assert(actual_string !~ /#{post_zero_noise}$/,
			"asciiz_to_str should ignore characters after zero")

		assert_equal(target_string, actual_string,
			"asciiz_to_str should only return the contents of the string before (exclusive) the zero")

		assert_equal(target_string, TEST_DLL_HELPER.asciiz_to_str(target_string),
			"asciiz_to_str should return input verbatim should that input not be zero-terminated")

	end

	def test_str_to_uni_z
		ruby_string = "If I were a rich man..."

		target_zero_terminated_unicode = Rex::Text.to_unicode(ruby_string) + "\x00\x00"
		actual_zero_terminated_unicode = TEST_DLL_HELPER.str_to_uni_z(ruby_string)

		assert(actual_zero_terminated_unicode =~ /\x00\x00$/,
			"str_to_uni_z should result in a double-zero terminated string")

		assert_equal(target_zero_terminated_unicode, actual_zero_terminated_unicode,
			"str_to_uni_z should convert ruby string to zero-terminated WCHAR string")
	end

	def test_uniz_to_str
		target_string = 'Foo bar baz'

		zero_terminated_unicode = Rex::Text.to_unicode(target_string) + "\x00\x00"

		assert_equal(target_string, TEST_DLL_HELPER.uniz_to_str(zero_terminated_unicode),
			'uniz_to_str should convert 0-terminated UTF16 to ruby string')

	end

	def test_assemble_buffer
		# TODO: provide test coverage 
		#skip("Currently DLLHelper.assemble_buffer does not have coverage")
	end

	def test_param_to_number
		consts_manager = WinConstManager.new

		x_key = 'X'
		x_value = 23

		y_key = 'Y'
		y_value = 5
		
		logical_or = x_key +  '|' +  y_key
		target_result_of_logical_or = x_value | y_value

		consts_manager.add_const(y_key, y_value)
		consts_manager.add_const(x_key, x_value)

		assert_equal(x_value, TEST_DLL_HELPER.param_to_number(x_key, consts_manager),
			"param_to_number should return the appropriate value for a given constant")

		assert_equal(y_value, TEST_DLL_HELPER.param_to_number(y_key, consts_manager),
			"param_to_number should return the appropriate value for a given constant")

		assert_equal(0, TEST_DLL_HELPER.param_to_number(nil, consts_manager),
			"param_to_number should return zero when given nil")

		assert_equal(target_result_of_logical_or, TEST_DLL_HELPER.param_to_number(logical_or, consts_manager),
			"param_to_number should perform an OR should the input be in the form '#{logical_or}'")

		assert_raise(ArgumentError, 'param_to_number should raise an error when a given key does not exist') do
			TEST_DLL_HELPER.param_to_number('DOESNT_EXIST', consts_manager)
		end
	end
end
end
end
end
end
end
end
