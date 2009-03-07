require 'metasm'

src = ARGV.empty? ? <<EOS : ARGF.read
void foo(int);
void bla()
{
	int i = 10;
	while (--i)
		foo(i);
}
EOS

cp = Metasm::C::Parser.parse src
puts cp, '', ' ----', ''
cp.precompile
puts cp, '', ' ----', ''

cp = Metasm::C::Parser.parse src
cpu = Metasm::Ia32.new
cpu.generate_PIC = false
puts cpu.new_ccompiler(cp).compile
