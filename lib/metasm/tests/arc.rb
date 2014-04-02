#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'test/unit'
require 'metasm'

class TestArc < Test::Unit::TestCase
  def test_arc_dec
    hex_stream =  "\x0A\x23\x80\x0F\x80\x0\x60\x0D" # mov r3, 0x800D60
    hex_stream += "\x40\x83"          # ld_s r2, [r3, 0]

    dasm = Metasm::Shellcode.disassemble(Metasm::ARC.new, hex_stream)
    assert_equal(2, dasm.decoded.length)

    assert_equal('mov', dasm.decoded[0].instruction.opname)
    assert_equal('r3', dasm.decoded[0].instruction.args[0].to_s)
    assert_equal(0x800d60, dasm.decoded[0].instruction.args[1].reduce)

    assert_equal('ld_s', dasm.decoded[8].instruction.opname)
    assert_equal('r2', dasm.decoded[8].instruction.args[0].to_s)
    assert_equal('r3', dasm.decoded[8].instruction.args[1].base.to_s)
    assert_equal(0, dasm.decoded[8].instruction.args[1].disp.reduce)
  end
end
