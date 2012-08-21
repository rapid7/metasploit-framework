#!/usr/bin/env ruby
# -*- coding: binary -*-

$:.unshift(File.join(File.dirname(__FILE__), '..', '..','..','..','..','..', '..', '..', 'lib'))

require 'rex/post/meterpreter/extensions/stdapi/railgun/type/pointer_util'
require 'rex/post/meterpreter/extensions/stdapi/railgun/platform_util'
require 'rex/post/meterpreter/extensions/stdapi/railgun/mock_magic'
require 'test/unit'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Type
class PlatformUtil::UnitTest < Test::Unit::TestCase

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

	X86_64 = PlatformUtil::X86_64
	X86_32 = PlatformUtil::X86_32

	def test_pack_pointer
		X86_64_POINTERS.invert.each_pair do |unpacked, packed|
			assert_equal(packed, PointerUtil.pack_pointer(unpacked.to_i, X86_64),
				"pack_pointer should pack 64-bit numberic pointers")
		end

		X86_32_POINTERS.invert.each_pair do |unpacked, packed|
			assert_equal(packed, PointerUtil.pack_pointer(unpacked.to_i, X86_32),
				"pack_pointer should pack 32-bit numberic pointers")
		end

		assert_equal(X86_64_NULL_POINTER, PointerUtil.pack_pointer(nil, X86_64),
			'pack_pointer should pack "nil" as a null pointer for x86_64')

		assert_equal(X86_32_NULL_POINTER, PointerUtil.pack_pointer(nil, X86_32),
			'pack_pointer should pack "nil" as a null pointer for x86_32')

		assert_equal(X86_64_NULL_POINTER, PointerUtil.pack_pointer(0, X86_64),
			'pack_pointer should pack numeric 0 as a null pointer for x86_64')

		assert_equal(X86_32_NULL_POINTER, PointerUtil.pack_pointer(0, X86_32),
			'pack_pointer should pack numeric 9 as a null pointer for x86_32')
	end

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
		assert_equal(8, PointerUtil.pointer_size(X86_64),
			'pointer_size should report X86_64 arch as 8 (bytes)')

		assert_equal(4, PointerUtil.pointer_size(X86_32),
			'pointer_size should report X86_32 arch as 4 (bytes)')
	end

	def test_is_pointer_type
		assert_equal(true, PointerUtil.is_pointer_type?(:pointer),
			'pointer_type should return true for the symbol :pointer')

		assert_equal(true, PointerUtil.is_pointer_type?('LPVOID'),
			'pointer_type should return true if string begins with LP')

		assert_equal(true, PointerUtil.is_pointer_type?('PDWORD'),
			'pointer_type should return true if string begins with P')

		assert_equal(false, PointerUtil.is_pointer_type?('LOLZ'),
			'pointer_type should return false if not a pointer type')

	end
end
end
end
end
end
end
end
end
