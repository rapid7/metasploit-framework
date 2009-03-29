#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

#
# this sample shows how to compile an executable file from source
# use --exe PE to compile a PE/ELF/MachO etc
# use --cpu MIPS/--16/--be to change the CPU
# the arg is a source file (c or asm) (some arch may not yet support C compiling)
#

require 'metasm'
require 'optparse'

$execlass ||= Metasm::ELF
$cpu ||= Metasm::Ia32.new

outfilename = 'a.out'
type = nil
OptionParser.new { |opt|
	opt.on('-o file') { |f| outfilename = f }
	opt.on('--c') { type = 'c' }
	opt.on('--asm') { type = 'asm' }
	opt.on('-v', '-W') { $VERBOSE=true }
	opt.on('-d') { $DEBUG=$VERBOSE=true }
	opt.on('-e class', '--exe class') { |c| $execlass = Metasm.const_get(c) }
	opt.on('--cpu cpu') { |c| $cpu = Metasm.const_get(c).new }
	# must come after --cpu in commandline
	opt.on('--16') { $cpu.size = 16 }
	opt.on('--le') { $cpu.endianness = :little }
	opt.on('--be') { $cpu.endianness = :big }
}.parse!

if file = ARGV.shift
	src = File.read(file)
	type ||= 'c' if file =~ /\.c$/
else
	src = DATA.read	# the text after __END__
end

if type == 'c'
	exe = $execlass.compile_c($cpu, src, file)
else
	exe = $execlass.assemble($cpu, src, file)
end
exe.encode_file(outfilename)

__END__
.text
.entrypoint
push bla
push fmt
call printf
push 0
call exit

.data
bla db "world", 0
fmt db "Hello, %s !\n", 0
