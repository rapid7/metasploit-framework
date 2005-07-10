#!/usr/bin/ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

require 'test/unit'
require 'rex/string_utils'
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

	def test_check_reg
		assert_raise(::ArgumentError) { Klass.check_reg(8) }
		assert_raise(::ArgumentError) { Klass.check_reg(-1) }

		0.upto(7) { |reg|
			assert_nothing_raised { Klass.check_reg(reg) }
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

end
