#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

require 'test/unit'
require 'rex/text'
require 'rex/assembly/nasm'

class Rex::Assembly::Nasm::UnitTest < ::Test::Unit::TestCase

	Klass = Rex::Assembly::Nasm

	def test_assemble
		assert_equal("\x31\xc0", Klass.assemble("xor eax, eax"))
	end

	def test_disassemble
		assert_equal("00000000  31C0              xor eax,eax\n", Klass.disassemble("\x31\xc0"))
	end

end
