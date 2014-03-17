#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'test/unit'
require 'metasm'

class TestX86_64 < Test::Unit::TestCase
  @@cpu = Metasm::X86_64.new
  def assemble(src, cpu=@@cpu)
    Metasm::Shellcode.assemble(cpu, src).encode_string
  end

  def test_user
    assert_equal(Metasm::X86_64, Metasm::Ia32.new(64).class)
  end

  def test_basic
    assert_equal("\x90", assemble("nop"))
    assert_equal("\x50", assemble("push rax"))
    assert_equal("\x41\x50", assemble("push r8"))
    assert_equal("\x6a\x02", assemble("push 2"))
    assert_equal("\x68\x8e\0\0\0", assemble("push 142"))
    assert_equal("\x48\xbb\xef\xcd\xab\x89\x67\x45\x23\x01", assemble("mov rbx, 0123456789abcdefh"))
    assert_equal("\x8d\x05\x0c\0\0\0", assemble("lea eax, [rip+12]"))
    assert_equal("\x8d\x04\x25\x0c\0\0\0", assemble("lea eax, [12]"))
  end

  def test_err
    assert_raise(Metasm::ParseError) { assemble("add eax") }
    assert_raise(Metasm::ParseError) { assemble("add add, ebx") }
    assert_raise(Metasm::ParseError) { assemble("add 42, ebx") }
    assert_raise(Metasm::ParseError) { assemble("add [bx]") }
    assert_raise(Metasm::ParseError) { assemble("add [eip+4*eax]") }
    assert_raise(Metasm::ParseError) { assemble("add ah, r8b") }
  end

  def disassemble(bin, cpu=@@cpu)
    Metasm::Shellcode.disassemble(cpu, bin)
  end

  def test_dasm
    d = disassemble("\x90")
    assert_equal(Metasm::DecodedInstruction, d.decoded[0].class)
    assert_equal('nop', d.decoded[0].opcode.name)
  end

  def test_rex
    assert_equal("\xfe\xc0", assemble("inc al"))
    assert_equal("\xfe\xc4", assemble("inc ah"))
    assert_equal("\x40\xfe\xc4", assemble("inc spl"))
    assert_equal("\x41\xfe\xc4", assemble("inc r12b"))
    op = lambda { |s| i = disassemble(s).decoded[0].instruction ; i.to_s ; i.args.last.to_s }
    assert_equal('al', op["\xfe\xc0"])
    assert_equal('ah', op["\xfe\xc4"])
    assert_equal('spl', op["\x40\xfe\xc4"])
    assert_equal('r12b', op["\x41\xfe\xc4"])
    assert_equal('[rip-6+12h]', op["\x8d\x05\x0c\0\0\0"])
  end
end
