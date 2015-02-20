#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'test/unit'
require 'metasm'

class TestDynldr < Test::Unit::TestCase
  def d; Metasm::DynLdr; end

  def test_new_api_c
    str = "1234"
    d.new_api_c('int memcpy(char*, char*, int)')
    d.memcpy(str, "9999", 2)
    assert_equal('9934', str)
  end

  def test_new_func_c
    c_src = <<EOS
int sprintf(char*, char*, ...);			// stdlib external
void fufu(int i, char* ptr)
{
  static int meh;				// .data
  meh = i;
  sprintf(ptr, "lolzor %i\\n", meh);	// string constant = .rodata
}
EOS
    buf = 'aaaaaaaaaaaaaaaaaa'
    d.new_func_c(c_src) { d.fufu(42, buf) }
    assert_equal("lolzor 42\n\000aaaaaaa", buf)
  end

  def test_new_func_asm
    if d.host_cpu.shortname == 'ia32'
      ret = d.new_func_asm('int __fastcall bla(int)', "lea eax, [ecx+1]\nret") { d.bla(42) }
      assert_equal(43, ret)
      assert_equal(false, d.respond_to?(:bla))
    end
  end

  def test_callback
    c1 = d.callback_alloc_c('int lol(int);') { |i| i+1 }
    c2 = d.callback_alloc_c('int lol(int);') { |i| i+2 }
    c3 = d.callback_alloc_c('int lol(int);') { |i| i/2 }

    d.new_func_c "int blop(int i, int (*fp)(int)) { return fp(i); }"
    
    assert_equal(2, d.blop(1, c1))
    assert_equal(4, d.blop(2, c2))
    assert_equal(6, d.blop(13, c3))
  end
end
