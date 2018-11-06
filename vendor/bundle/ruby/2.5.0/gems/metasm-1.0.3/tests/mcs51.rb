#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2015 Google
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'test/unit'
require 'metasm'


class TestMCS51 < Test::Unit::TestCase
	def test_mcs51_dec
		hex_stream =  "\x09\x00\x1F" # inc; nop; dec
		hex_stream += "\x58\xF9\xEC\x32\x36\xc4\xa5\x24\x02\x45\x03"
		hex_stream += "\x84\xa4\xc5\xa5\x70\xfe"
		hex_stream += "\xba\x04\x08"
		hex_stream += "\xc0\x04"
		hex_stream += "\x11\x23"
		hex_stream += "\xa1\x88"
		hex_stream += "\x62\x88"
		hex_stream += "\x53\x79\x66"
		hex_stream += "\x02\x12\x34"

		dasm = Metasm::Shellcode.disassemble(Metasm::MCS51.new, hex_stream)
		#puts dasm
		assert_equal(23, dasm.decoded.length)
	end
end
