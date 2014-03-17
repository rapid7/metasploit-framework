#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# shows the compilation phase step by step: c, simplified c, asm

require 'metasm'
require 'optparse'

opts = { :cpu => 'Ia32', :exe => 'Shellcode', :macros => {} }
OptionParser.new { |opt|
  opt.on('--pic', 'generate position-independant code') { opts[:pic] = true }
  opt.on('--cpu cpu') { |c| opts[:cpu] = c }
  opt.on('--exe exe') { |e| opts[:exe] = e }
  opt.on('-D var=val', 'define a preprocessor macro') { |v| v0, v1 = v.split('=', 2) ; opts[:macros][v0] = v1 }
  opt.on('-v') { $VERBOSE = true }
  opt.on('-d') { $VERBOSE = $DEBUG = true }
}.parse!(ARGV)

src = ARGV.empty? ? <<EOS : ARGF.read
void foo(int);
void bla()
{
  int i = 10;
  while (--i)
    foo(i);
}
EOS

pp = opts[:macros].map { |k, v| "#define #{k} #{v}" }.join("\n")

cpu = Metasm.const_get(opts[:cpu]).new
exe = Metasm.const_get(opts[:exe]).new(cpu)
cpu.generate_PIC = false unless opts[:pic]

cp = Metasm::C::Parser.new(exe)
cp.parse pp
cp.parse src
puts cp, '', ' ----', ''

cp.precompile
puts cp, '', ' ----', ''

cp = Metasm::C::Parser.new(exe)
cp.parse pp
cp.parse src
puts cpu.new_ccompiler(cp).compile
