#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'test/unit'
require 'metasm/preprocessor'
require 'metasm/parse'


# BEWARE OF TEH RUBY PARSER
# use single-quoted source strings
class TestPreproc < Test::Unit::TestCase
  def load txt, bt = caller.first
    p = Metasm::Preprocessor.new
    bt =~ /^(.*?):(\d+)/
    p.feed txt, $1, $2.to_i+1
    p
  end

  def test_gettok
    p = load <<'EOS'
test boo
" bla bla\
\"\\"   \
xx
EOS
    assert_equal \
    ['test', :space, :string, :eol, :quoted, :space, 'xx', :eol, true],
    [p.readtok.raw, p.readtok.type, p.readtok.type, p.readtok.type, p.readtok.type, p.readtok.type, p.readtok.raw, p.readtok.type, p.eos?]
  end

  def test_comment
    p = load <<'EOS'
foo /*/ bar ' " * /*/ baz
kikoo // lol \
asv
EOS
    toks = []
    nil while tok = p.readtok and (tok.type == :space or tok.type == :eol)
    until p.eos?
      toks << tok.raw
      nil while tok = p.readtok and (tok.type == :space or tok.type == :eol)
    end
    assert_equal %w[foo baz kikoo], toks
  end

  def helper_preparse(text, result)
    p = load(text, caller.first)
    yield p if block_given?
    txt = ''
    until p.eos? or not t = p.readtok
      txt << t.raw
           end
    assert_equal(result, txt.strip)
  end

  def test_preproc
    # ignores eol/space at begin/end
    helper_preparse(<<EOS, '')
#if 0  // test # as first char
toto
#endif
EOS
    helper_preparse(<<EOS, 'coucou')
#define tutu
#if defined ( tutu )
tutu coucou
#endif
EOS
    helper_preparse('a #define b', 'a #define b')
    helper_preparse(<<EOS, "// true !\nblu")
#ifdef toto // this is false
bla
#elif .2_3e-4 > 2 /* this one too */
blo
#elif (1+1)*2 > 2 // true !
blu
#elif 4 > 2 // not you
ble
#else
bli
#endif
EOS
    helper_preparse(<<'EOS', 'ab#define x')
a\
b\
#define x
EOS
    p = load('__LINE__,__DATE__,__TIME__')
    assert_equal(__LINE__, p.readtok.value) ; p.readtok
    assert_not_equal('__DATE__', p.readtok.raw) ; p.readtok
    assert_not_equal('__TIME__', p.readtok.raw)

    helper_preparse(<<EOS, 'toto 1 toto 12 toto 3+(3-2) otot hoho')
#define azer(k) 12
# define xxx azer(7)
#define macro(a, b, c) toto a toto b toto c otot
macro(1, xxx, 3+(3-2)) hoho
EOS
    helper_preparse(<<EOS, 'c')
#define a b
#define d c
#define c d
#define b c
a
EOS
    helper_preparse(<<EOS, 'b')
#define b c
#define a b
#undef b
a
EOS
    helper_preparse(<<EOS, 'toto tutu huhu()')
#define toto() abcd
#define tata huhu
toto tutu tata()
EOS
    helper_preparse(<<EOS, '"haha"')
#define d(a) #a
d(haha)
EOS
    helper_preparse(<<EOS, '{')
#define toto(a) a
toto({)
EOS
    helper_preparse(<<EOS, 'x(, 1)')
#define d(a,b) x(a, b)
d(,1)
EOS
    helper_preparse(<<EOS, '"foo" "4"')
#define str(x) #x
#define xstr(x) str(x)
#define foo 4
str(foo) xstr(foo)
EOS
    begin
      File.open('tests/prepro_testinclude.asm', 'w') { |fd| fd.puts '#define out in' }
      helper_preparse(<<EOS, 'in')
#pragma include_path "."
#include <tests/prepro_testinclude.asm>
out
EOS
    ensure
      File.unlink('tests/prepro_testinclude.asm') rescue nil
    end

    helper_preparse(<<EOS, 'in') { |p_| p_.hooked_include['bla.h'] = '#define out in' }
#include <bla.h>
out
EOS
    helper_preparse(<<EOS, 'in') { |p_| p_.define('out', 'in') }
out
EOS
    helper_preparse(<<EOS, 'in') { |p_| p_.define_strong('out', 'in') }
out
EOS
    helper_preparse(<<EOS, 'in') { |p_| p_.define_strong('out', 'in') }
#define out poil
out
EOS
    helper_preparse(<<EOS, 'in') { |p_| p_.define('out', 'in') ; p_.define_weak('out', 'poil') }
out
EOS
    p = load <<EOS
#define cct(a, b) a ## _ ## b
cct(toto, tutu)
EOS
    nil while tok = p.readtok and (tok.type == :space or tok.type == :eol)
    assert_equal('toto_tutu', tok.raw)	# check we get only 1 token back

    # assert_outputs_a_warning ?
    helper_preparse(<<EOS, <<EOS.strip)
#define va1(a, b...) toto(a, ##b)
#define va3(a, ...)  toto(a, __VA_ARGS__)
va1(1, 2);
va1(1,2);
va1(1);
va3(1, 2);
va3(1);
EOS
toto(1, 2);
toto(1,2);
toto(1);
toto(1, 2);
toto(1, );
EOS

    helper_preparse(<<EOS, "#define a c\n#define b d\na b")
#define x(z) z
#define y #define
x(#)define a c
y b d
a b
EOS
    helper_preparse("#define a(a) a(a)\na(1)", '1(1)')
    helper_preparse("#if 0\n#endif", '')
    helper_preparse("#if 0U\n#endif", '')
    helper_preparse("#if 0L\n#endif", '')
    helper_preparse("#if 0LLU\n#endif", '')
  end

  def test_floats
    t_float = lambda { |txt|
      text = <<EOS
#if #{txt}
1
#endif
EOS
      p = load text, caller.first
      txt = ''
      t = nil
      txt << t.raw until p.eos? or not t = p.readtok
      assert_equal('1', txt.strip)
    }
    t_float['1 > 0']
    t_float['1.0 > 0']
    t_float['1e2 > 10 && 1.0e2 < 1000']
    t_float['1.0e+2 > 10']
    t_float['10_00e-2 > 1 && 10_00e-2 < 100']
    t_float['.1e2 > 1']
    #t_float['0x1.p2L > 1 && 0x1p2f < 5']
    t_float['0x1.p2L > 1']
    t_float['0x1p2f < 5']
  end

  def test_errors
    test_err = lambda { |txt| assert_raise(Metasm::ParseError) { p = load(txt, caller.first) ; p.readtok until p.eos? } }
    t_float = lambda { |txt| assert_raise(Metasm::ParseError) { p = load("#if #{txt}\n#endif", caller.first) ; p.readtok } }
    test_err["\"abc\n\""]
    test_err['"abc\x"']
    test_err['/*']
    test_err['#if 0']
    test_err["#define toto(tutu,"]
    test_err["#define toto( (tutu, tata)"]
    test_err['#error bla']
    test_err[<<EOS]
#if 0
#elif 1
#else
#if 2
#endif
EOS
    test_err[<<EOS]
#define abc(def)
abc (1, 3)
EOS
    test_err["#if 0LUL\n#endif"]
    # warnings only
    #test_err["#define aa\n#define aa"]
    #test_err['#define a(b) #c']
    #test_err['#define a(b, b)']
    #test_err['#define a ##z']
    t_float['1e++4']
    t_float['1.0e 4']
    t_float['_1.0']
    t_float['.e2']
    t_float['1.1e+_1']
    t_float['.2e']
    t_float['.']
    t_float['1.2e*4']
    t_float['0x1.e4']
    t_float['0x1.p4a']
    t_float['0x.p1']
    t_float['0x.1lp1']
  end
end

