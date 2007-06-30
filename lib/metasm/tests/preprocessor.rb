#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'test/unit'
require 'metasm/preprocessor'


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
foo /* bar * /*/ baz
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

	def test_preproc
		# ignores eol/space at begin/end
		t_preparse = proc { |text, result|
			p = load text, caller.first
			txt = ''
			t = nil
			txt << t.raw until p.eos? or not t = p.readtok
			assert_equal(result, txt.strip)
		}
		t_preparse[<<EOS, '']
#if 0  // test # as first char
toto
#endif
EOS
		t_preparse[<<EOS, 'coucou']
#define tutu
#if defined ( tutu )
coucou
#endif
EOS
		t_preparse['a #define b', 'a #define b']
		t_preparse[<<EOS, "// true !\nblu"]
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
		t_preparse[<<'EOS', 'ab#define x']
a\
b\
#define x
EOS
		p = load('__LINE__')
		assert_equal(__LINE__.to_s, p.readtok.value)
		t_preparse[<<EOS, 'toto 1 toto 12 toto 3+(3-2) otot hoho']
#define azer(k) 12
# define xxx azer(7)
#define macro(a, b, c) toto a toto b toto c otot
macro(1, xxx, 3+(3-2)) hoho
EOS
		t_preparse[<<EOS, 'c']
#define a b
#define d c
#define c d
#define b c
a
EOS
		t_preparse[<<EOS, 'b']
#define b c
#define a b
#undef b
a
EOS
		t_preparse[<<EOS, 'toto tutu']
#define toto() abcd
toto tutu
EOS
		t_preparse[<<EOS, '"haha"']
#define d(a) #a
d(haha)
EOS
		t_preparse[<<EOS, '{']
#define toto(a) a
toto({)
EOS
		t_preparse[<<EOS, 'x(, 1)']
#define d(a,b) x(a, b)
d(,1)
EOS
		Metasm::Preprocessor.include_search_path << '.'
		begin
			File.open('tests/prepro_testinclude.asm', 'w') { |fd| fd.puts '#define out in' }
			t_preparse[<<EOS, 'in']
#include <tests/prepro_testinclude.asm>
out
EOS
		ensure
			File.unlink('tests/prepro_testinclude.asm') rescue nil
		end

		p = load <<EOS
#define cct(a, b) a ## _ ## b
cct(toto, tutu)
EOS
		nil while tok = p.readtok and (tok.type == :space or tok.type == :eol)
		assert_equal('toto_tutu', tok.raw)	# check we get only 1 token back

		# assert_outputs_a_warning ?
		t_preparse[<<EOS, <<EOS.strip]
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

		t_preparse[<<EOS, "#define a c\n#define b d\na b"]
#define x(z) z
#define y #define
x(#)define a c
y b d
a b
EOS
		t_preparse["#define a(a) a(a)\na(1)", '1(1)']
		t_preparse["#if 0\n#endif", '']
	end

	def test_errors
		test_err = proc { |txt| assert_raise(Metasm::ParseError) { p = load(txt, caller.first) ; p.readtok until p.eos? } }
		test_err["\"abc\n\""]
		test_err['"abc\x"']
		test_err['/*']
		test_err['#if 0']
		test_err["#if 0.\n#end"]
		test_err["#if 0.3e\n#end"]
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
		# warnings only
		#test_err["#define aa\n#define aa"]
		#test_err['#define a(b) #c']
		#test_err['#define a(b, b)']
		#test_err['#define a ##z']
	end
end

