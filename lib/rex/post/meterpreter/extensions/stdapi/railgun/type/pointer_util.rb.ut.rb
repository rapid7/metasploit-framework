#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..','..','..','..','..', '..', '..', 'lib')) 

require 'rex/post/meterpreter/extensions/stdapi/railgun/type/pointer_util'
require 'rex/post/meterpreter/extensions/stdapi/railgun/mock_magic'
require 'test/unit'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Type
class PointerUtil::UnitTest < Test::Unit::TestCase

	include Rex::Post::Meterpreter::Extensions::Stdapi::Railgun::MockMagic
	
	# memread value of win x86 pointer mapped to target unpack value
	X86_32_POINTERS = {
		"8D\x15\x00"       => 1393720,
		"\x1C\x84\x15\x00" => 1410076,
		"\x0E\x84\x15\x00" => 1410062, 
		"\x02\x84\x15\x00" => 1410050, 
		"\xE6\x83\x15\x00" => 1410022, 
		"\xC4\x83\x15\x00" => 1409988,
		"\x00\x00\x00\x00" => 0,
	}
	X86_64_POINTERS = {
		"\x10^ \x00\x00\x00\x00\x00"       => 2121232,
		"\xCA\x9D \x00\x00\x00\x00\x00"    => 2137546,
		"\xC8\x9D \x00\x00\x00\x00\x00"    => 2137544,
		"Z\x9D \x00\x00\x00\x00\x00"       => 2137434,
		"X\x9D \x00\x00\x00\x00\x00"       => 2137432,
		"\x00\x00\x00\x00\x00\x00\x00\x00" => 0,
	}

	X86_64_NULL_POINTER = "\x00\x00\x00\x00\x00\x00\x00\x00"
	X86_32_NULL_POINTER = "\x00\x00\x00\x00"

	X86_64 = :x86_64
	X86_32 = :x86_32

	def test_unpack_pointer
		X86_64_POINTERS.each_pair do |packed, unpacked|
			assert_equal(unpacked, PointerUtil.unpack_pointer(packed, X86_64), 
				"unpack_pointer should unpack 64-bit pointers")
		end

		X86_32_POINTERS.each_pair do |packed, unpacked|
			assert_equal(unpacked, PointerUtil.unpack_pointer(packed, X86_32), 
				"unpack_pointer should unpack 32-bit pointers")
		end
	end

	def test_is_null_pointer
		[X86_32, X86_64].each do |platform|
			assert(PointerUtil.is_null_pointer?(nil, platform), 'nil should be a null pointer')
			assert(PointerUtil.is_null_pointer?(0, platform), 'numeric 0 should be a null pointer')
		end

		assert_equal(true, PointerUtil.is_null_pointer?(X86_32_NULL_POINTER, X86_32),
			'is_null_pointer? should return true for packed 32-bit null pointers')

		assert_equal(true, PointerUtil.is_null_pointer?(X86_64_NULL_POINTER, X86_64),
			'is_null_pointer? should return true for packed 64-bit null pointers')

	end	

	def test_pointer_size
	end
end
end
end
end
end
end
end
end
