#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

require 'test/unit'
require 'rex/text'
require 'rex/assembly/nasm'

class Rex::Assembly::Nasm::UnitTest < ::Test::Unit::TestCase

	Klass = Rex::Assembly::Nasm

	def test_assemble
		assert_equal("\x6a\x00", Klass.assemble("push byte 0x00"))
		assert_equal("\xb2\xb4", Klass.assemble("mov dl, 0xb4"))
	end

	def test_disassemble
		assert_equal("00000000  31C0              xor eax,eax\n", Klass.disassemble("\x31\xc0"))
	end

end