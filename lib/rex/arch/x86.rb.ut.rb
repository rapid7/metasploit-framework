#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

require 'test/unit'
require 'rex/text'
require 'rex/arch/x86'

class Rex::Arch::X86::UnitTest < ::Test::Unit::TestCase

	Klass = Rex::Arch::X86

	def test_reg_number
		assert_equal(Klass.reg_number('eax'), Klass::EAX)
		assert_equal(Klass.reg_number('EsP'), Klass::ESP)
	end

	def test_push_byte
		assert_raise(::ArgumentError) { Klass.push_byte(-129) }
		assert_raise(::ArgumentError) { Klass.push_byte(8732) }
		assert_equal("\x6a\x10", Klass.push_byte(16))
		assert_equal("\x6a\xff", Klass.push_byte(-1))
	end

	def test_push_dword
		assert_equal("\x68\x78\x56\x34\x12", Klass.push_dword(0x12345678))
	end

	def test_mov_dword
		assert_equal("\xb8\x78\x56\x34\x12", Klass.mov_dword(Klass::EAX, 0x12345678))
	end

	def test_mov_word
		assert_equal("\x66\xbc\x37\x13", Klass.mov_word(Klass::SP, 0x1337))
	end

	def test_mov_byte
		assert_raise(::RangeError) { Klass.mov_byte(Klass::AL, 0x100) }
		assert_raise(::RangeError) { Klass.mov_byte(Klass::AL, -1) }
		assert_equal("\xb2\xb2", Klass.mov_byte(Klass::DL, 0xb2))
	end

	def test_check_reg
		assert_raise(::ArgumentError) { Klass._check_reg(8) }
		assert_raise(::ArgumentError) { Klass._check_reg(-1) }

		0.upto(7) { |reg|
			assert_nothing_raised { Klass._check_reg(reg) }
		}
	end

	def test_pop_dword
		assert_raise(::ArgumentError) { Klass.pop_dword(8) }
		assert_raise(::ArgumentError) { Klass.pop_dword(-1) }

		assert_equal("\x58", Klass.pop_dword(Klass::EAX))
		assert_equal("\x5a", Klass.pop_dword(Klass::EDX))
		assert_equal("\x5c", Klass.pop_dword(Klass::ESP))
	end

	def test_sub
		assert_equal("\x83\xe8\x04", Klass.sub(4, Klass::EAX)[2, 3])
		assert_equal("\x66\x81\xe8\x80\xff", Klass.sub(-128, Klass::EAX)[2, 5])
		assert_equal("\x81\xe8\x00\x00\x01\x00", Klass.sub(65536, Klass::EAX)[2, 6])
	end

	def test_add
		assert_equal("\x83\xc4\x47", Klass.add(0x47, Klass::ESP)[2,6])
		assert_equal("\x83\xc4\x47", Klass.add(0x47, Klass::ESP, '', true))
		assert_equal("\x81\xc4\x11\x11\x01\x00", Klass.add(0x11111, Klass::ESP, '', true))
	end

	def test_clear
		assert_equal("\x33\xc0", Klass.clear(Klass::EAX, "\x29\x2b\x31"))
	end
	
	def test_searcher
			s = "\xbe"+                  # mov esi, Tag - 1
			"\x03\x03\x02\x01"+
			"\x46"+                      # inc esi
			"\x47"+                      # inc edi (end_search:)
			"\x39\x37"+                  # cmp [edi],esi
			"\x75\xfb"+                  # jnz 0xa (end_search)
			"\x46"+                      # inc esi
			"\x4f"+                      # dec edi (start_search:)
			"\x39\x77\xfc"+              # cmp [edi-0x4],esi
			"\x75\xfa"+                  # jnz 0x10 (start_search)
			"\xff\xe7"                   # jmp edi	
						
		assert_equal(s, Klass.searcher("\x04\x03\x02\x01"))
	end

end