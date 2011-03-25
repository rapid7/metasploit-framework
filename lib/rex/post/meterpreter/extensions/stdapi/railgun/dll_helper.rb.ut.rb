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
	TEST_DLL_HELPER = Object.new.extend(DLLHelper)

	def test_str_to_ascii_z
		original_string = '23 Skidoo!'

		# converts ruby string to zero-terminated ASCII string
		zero_terminated_ascii_attempt = TEST_DLL_HELPER.str_to_ascii_z(original_string)

		assert(zero_terminated_ascii_attempt.end_with?("\x00"), 
			"should result in a 0 terminated string")

		assert(zero_terminated_ascii_attempt.start_with?(original_string), 
			"should still start with original string")

		assert_equal(original_string.length + 1, zero_terminated_ascii_attempt.length, 
			"should have length of original pluss room for a terminal 0")
	end

	def test_asciiz_to_str
		target_string = '23 Skidoo!'
		post_zero_noise = 'Loud noises!'
		zero_terminated_string = target_string + "\x00" + post_zero_noise

		actual_string =  TEST_DLL_HELPER.asciiz_to_str(zero_terminated_string)

		assert(actual_string.start_with?(target_string),
			"should preserve string before zero")

		assert(!actual_string.end_with?(post_zero_noise),
			"should ignore characters after zero")

		assert_equal(target_string, actual_string,
			"should only return the contents of the string before (exclusive) the zero")

		assert_equal(target_string, TEST_DLL_HELPER.asciiz_to_str(target_string),
			"should return input verbatim should that input not be zero-terminated")

	end

	def test_str_to_uni_z
		ruby_string = "If I were a rich man..."

		target_zero_terminated_unicode = Rex::Text.to_unicode(ruby_string) + "\x00\x00"
		actual_zero_terminated_unicode = TEST_DLL_HELPER.str_to_uni_z(ruby_string)

		assert(actual_zero_terminated_unicode.end_with?("\x00\x00"),
			"should result in a double-zero terminated string")

		assert_equal(target_zero_terminated_unicode, actual_zero_terminated_unicode,
			"should convert ruby string to zero-terminated WCHAR string")
	end

	def test_uniz_to_str
		target_string = 'Foo bar baz'

		zero_terminated_unicode = Rex::Text.to_unicode(target_string) + "\x00\x00"

		assert_equal(target_string, TEST_DLL_HELPER.uniz_to_str(zero_terminated_unicode),
			'should convert 0-terminated UTF16 to ruby string')

	end

	def test_assemble_buffer
		# TODO: provide test coverage 
		#assert(false, "Should have test coverage for TEST_DLL_HELPER.assemble_buffer")
	end

	def test_param_to_number
		consts_manager = WinConstManager.new

		consts_manager.add_const('TWENTY_THREE', 23)
		consts_manager.add_const('FIVE', 5)

		assert_equal(23, TEST_DLL_HELPER.param_to_number('TWENTY_THREE', consts_manager),
			"should return the appropriate value for a given constant")

		assert_equal(5, TEST_DLL_HELPER.param_to_number('FIVE', consts_manager),
			"should return the appropriate value for a given constant")

		assert_equal(0, TEST_DLL_HELPER.param_to_number(nil, consts_manager),
			"should return zero when given nil")

		assert_equal(23, TEST_DLL_HELPER.param_to_number('TWENTY_THREE | FIVE', consts_manager),
			"should perform an OR should the input be in the form 'X | Y', where X and Z are constants")

		assert_raise(ArgumentError, 'should foo') do
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
