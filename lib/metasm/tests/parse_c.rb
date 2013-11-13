#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'test/unit'
require 'metasm'

class TestDynldr < Test::Unit::TestCase
  def cp
    @cp ||= Metasm::Ia32.new.new_cparser
  end

  def test_parse_c
    assert_nothing_raised {
      cp.parse("static int i_1=42; __stdcall __int64 foo_1(const char*);")
    }

    assert_kind_of(Metasm::C::Function, cp.toplevel.symbol['foo_1'].type)

    assert_raise(Metasm::ParseError) { cp.parse("static extern int fu;") }
    cp.readtok until cp.eos?

    assert_nothing_raised { cp.parse("const volatile volatile const char const * const * blarg_0;") }

    assert_nothing_raised { cp.parse("void *ptr = &ptr;") }

    assert_raise(Metasm::ParseError) { cp.parse("void *ptr = ptr;") }
    cp.readtok until cp.eos?

    assert_nothing_raised { cp.parse("struct { int sz; } bla = { .sz = sizeof(bla) };") }

    assert_raise(Metasm::ParseError) { cp.parse("signed unsigned int fu;") }
    cp.readtok until cp.eos?

    assert_raise(Metasm::ParseError) { cp.parse("long long long fu;") }
    cp.readtok until cp.eos?

    assert_raise(Metasm::ParseError) { cp.parse("void badarg(int i, int i) {}") }
    cp.readtok until cp.eos?

    assert_raise(Metasm::ParseError) { cp.parse("struct strun; union strun;") }
    cp.readtok until cp.eos?

    assert_raise(Metasm::ParseError) { cp.parse <<EOS }
asm <<EOA
 foo
 EOA
EOS
    cp.readtok until cp.eos?

    assert_nothing_raised { cp.parse <<EOS }
asm <<-EOA
 foo
 EOA
EOS
  end

  def test_struct
    cp.parse <<EOS
struct foo_2 {
  __int32 a;
  __int8 b;
  __int32 c;
  __int8 d;
};

struct foo_3 {
  __int8 a;
  __int8 b;
  __int16 c;
  __int32 d;
};

struct foo_4 {
  __int32 a;
  __int8 b;
  __int32 c;
  __int8 d;
} __attribute__((packed));

union foo_5 {
  __int64;
  struct {
    __int8;
    __int8*;
  };
  struct {
    __int16[8];
  };
};
EOS
    assert_equal(16, cp.sizeof(cp.toplevel.struct['foo_2']))
    assert_equal(8, cp.toplevel.struct['foo_2'].offsetof(cp, 'c'))
    assert_equal(8,  cp.sizeof(cp.toplevel.struct['foo_3']))
    assert_equal(10, cp.sizeof(cp.toplevel.struct['foo_4']))
    assert_equal(4, cp.toplevel.struct['foo_4'].offsetof(cp, 'b'))
    assert_equal(5, cp.toplevel.struct['foo_4'].offsetof(cp, 'c'))
    assert_equal(16, cp.sizeof(cp.toplevel.struct['foo_5']))

    assert_raise(Metasm::ParseError) { cp.parse("struct foo_3 { __int32 a; };") }
    cp.readtok until cp.eos?
    assert_nothing_raised { cp.parse("struct foo_3 { __int8 a; __int8 b; __int16 c; __int32 d; };") }

    assert_nothing_raised {
      cp.parse <<EOS
struct scop { int i; };

void func1(void) {
  struct scop { __int64 j; __int64 z; };
  struct scop s;
  s.j = 0;
}

void func2(void) {
  struct scop s;
  s.i = 0;
}
EOS
    }
  end

  def test_bitfields
    cp.parse <<EOS
struct foo_bits {
  __int32 f0:4;
  __int32 :0;
  __int32 f1:4;
  __int32 f2:4;
  __int8  f3;
  __int32 f4:4;
  __int32 f5:30;
};

struct foo_n_bits {
  struct foo_bits;
};

struct foo2_bits {
  __int64 f0:30;
  __int64 f1:30;
  __int64 f2:30;
};

struct foo3_bits {
  __int16 f0:8;
  __int16 f1:4;
  __int16 f2:1;
};
EOS
    st = cp.toplevel.struct['foo_bits']
    assert_equal(20, cp.sizeof(st))
    assert_equal([0, 4], st.bitoffsetof(cp, 'f1'))
    assert_equal([4, 4], st.bitoffsetof(cp, 'f2'))
    assert_equal(8,  st.offsetof(cp, 'f3'))
    assert_equal(12,  st.offsetof(cp, 'f4'))
    assert_equal([0, 30],  st.bitoffsetof(cp, 'f5'))

    st = cp.toplevel.struct['foo_n_bits']
    assert_equal(20, cp.sizeof(st))
    assert_equal([0, 4], st.bitoffsetof(cp, 'f1'))
    assert_equal([4, 4], st.bitoffsetof(cp, 'f2'))
    assert_equal(8,  st.offsetof(cp, 'f3'))
    assert_equal(12,  st.offsetof(cp, 'f4'))
    assert_equal([0, 30],  st.bitoffsetof(cp, 'f5'))

    st = cp.toplevel.struct['foo2_bits']
    assert_equal([0, 30], st.bitoffsetof(cp, 'f0'))
    assert_equal([30, 30], st.bitoffsetof(cp, 'f1'))
    assert_equal([0, 30], st.bitoffsetof(cp, 'f2'))

    st = cp.toplevel.struct['foo3_bits']
    assert_equal(2, cp.sizeof(st))
  end

  def test_allocstruct
cp.parse <<EOS
struct foo_outer {
  int i;
  struct {
    int j;
    int k;
  } inner;
};
EOS
    s = cp.alloc_c_struct('foo_outer', :i => :size)
    assert_equal(12, s.sizeof)
    assert_equal(12, s.i)
    assert_raise(RuntimeError) { s.l = 42 }
    assert_nothing_raised { s.j = 0x12345678 }
    assert_nothing_raised { s.inner.k = 0x3333_3333 }
    assert_equal(4, s.inner.stroff)
    assert_equal("0C0000007856341233333333", s.str.unpack('H*')[0].upcase)
  end

  def test_cmpstruct
st = <<EOS
struct foo {
  struct foo *p;
  int i;
};

struct s1 {
  struct s2 *p;
};

struct s2 {
  struct s1 *p;
};
EOS
    cp.parse st
    cp.parse <<EOS
struct t1 {
  struct t2 *pt;
};
struct t2 {
  struct t1 *pt;
};
EOS

    cp2 = Metasm::Ia32.new.new_cparser
    cp2.parse(st)
    cp2.parse <<EOS
struct t1 {
  struct t2 *pt;
};
struct t2 {
  struct t3 *pt;
};
struct t3 {
  struct t1 *pt;
};
EOS
    assert_equal(true, cp.toplevel.struct['foo'] == cp2.toplevel.struct['foo'])
    assert_equal(true, cp.toplevel.struct['s1'].compare_deep(cp2.toplevel.struct['s1']))
    assert_equal(true, cp.toplevel.struct['t1'] == cp2.toplevel.struct['t1'])	# expected failure
    assert_equal(false, !!cp.toplevel.struct['t1'].compare_deep(cp2.toplevel.struct['t1']))
  end
end
