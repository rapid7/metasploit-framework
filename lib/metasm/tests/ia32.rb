#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'test/unit'
require 'metasm'

class TestIa32 < Test::Unit::TestCase
  @@cpu32 = Metasm::Ia32.new
  @@cpu16 = Metasm::Ia32.new(16)
  def assemble(src, cpu=@@cpu32)
    Metasm::Shellcode.assemble(cpu, src).encode_string
  end

  def assert_equal(a, b) super(b, a) end

  def test_basic
    assert_equal(assemble("nop"), "\x90")
    assert_equal(assemble("push eax"), "\x50")
    assert_equal(assemble("push 2"), "\x6a\x02")
    assert_equal(assemble("push 142"), "\x68\x8e\0\0\0")
  end

  def test_sz
    assert_equal(assemble("dec eax"), "\x48")
    assert_equal(assemble("dec ax"), "\x66\x48")
    assert_equal(assemble("dec al"), "\xfe\xc8")
    assert_equal(assemble("arpl [edi+70h], bp"), "cop")
  end

  def test_16
    assert_equal(assemble("push 142", @@cpu16), "\x68\x8e\0")
    assert_equal(assemble("code16 push 142", @@cpu16), "\x68\x8e\0")
    assert_equal(assemble("code16 push 142"), "\x68\x8e\0")
    assert_equal(assemble("push.i16 142"), "\x66\x68\x8e\0")
    assert_equal(assemble("mov eax, 42"), "\xb8\x2a\0\0\0")
    assert_equal(assemble("code16 mov ax, 42"), "\xb8\x2a\0")
  end

  def test_jmp
    assert_equal(assemble("jmp $"), "\xeb\xfe")
    assert_equal(assemble("jmp.i32 $"), "\xe9\xfb\xff\xff\xff")
  end

  def test_mrmsz
    assert_equal(assemble("mov [eax], ebx"), "\x89\x18")
    assert_equal(assemble("mov [eax], bl"), "\x88\x18")
    assert_equal(assemble("mov ebx, [eax]"), "\x8b\x18")
    assert_equal(assemble("mov bl, [eax]"), "\x8a\x18")
    assert_equal(assemble("mov bl, [bx]"), "\x67\x8a\x1f")
    assert_equal(assemble("mov bl, [bx]", @@cpu16), "\x8a\x1f")
    assert_equal(assemble("code16 mov bl, [bx]"), "\x8a\x1f")
    assert_equal(assemble("mov bl, [0]"), "\x8a\x1d\0\0\0\0")
    assert_equal(assemble("mov.a16 bl, [0]"), "\x67\x8a\x1e\0\0")
  end

  def test_err
    assert_raise(Metasm::ParseError) { assemble("add eax") }
    assert_raise(Metasm::ParseError) { assemble("add add, ebx") }
    assert_raise(Metasm::ParseError) { assemble("add 42, ebx") }
    assert_raise(Metasm::ParseError) { assemble("add [bx+ax]") }
  end

  def test_C
    src = "int bla(void) { volatile int i=0; return ++i; }"
    assert_equal(Metasm::Shellcode.compile_c(@@cpu32, src).encode_string,
        ["5589E583EC04C745FC00000000FF45FC8B45FC89EC5DC3"].pack('H*'))
  end

  def disassemble(bin, cpu=@@cpu32)
    Metasm::Shellcode.disassemble(cpu, bin)
  end

  def test_dasm
    d = disassemble("\x90")
    assert_equal(d.decoded[0].class, Metasm::DecodedInstruction)
    assert_equal(d.decoded[0].opcode.name, "nop")
  end

end
