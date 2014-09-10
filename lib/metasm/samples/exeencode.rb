#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

#
# this sample shows how to compile an executable file from source
# use --exe PE to compile a PE/ELF/MachO etc
# use --cpu MIPS/--16/--be to change the CPU
# the arg is a source file (c or asm) (some arch may not yet support C compiling)
# defaults to encoding a shellcode, use --exe to override (or the scripts samples/{elf,pe}encode)
# to compile a shellcode to a cstring, use --cstring
#

require 'metasm'
require 'optparse'

$opts ||= {}
$opts = {
 :execlass => Metasm::Shellcode,
 :cpu => Metasm::Ia32.new,
 :exetype => :bin,
 :macros => {}
}.merge($opts)

OptionParser.new { |opt|
  opt.on('-o file', 'output filename') { |f| $opts[:outfilename] = f }
  opt.on('-i', 'dont overwrite existing outfile') { $opts[:nooverwrite_outfile] = true }
  opt.on('-f', 'overwrite existing outfile (default)') { $opts.delete :nooverwrite_outfile }	# without this, optparse autocomplete to --fno-pic and break older scripts...
  opt.on('--c', 'parse source as a C file') { $opts[:srctype] = 'c' }
  opt.on('--asm', 'parse asm as an ASM file') { $opts[:srctype] = 'asm' }
  opt.on('--stdin', 'parse source on stdin') { ARGV << '-' }
  opt.on('-v', '-W', 'verbose') { $VERBOSE=true }
  opt.on('-d', 'debug') { $DEBUG=$VERBOSE=true }
  opt.on('-D var=val', 'define a preprocessor macro') { |v| v0, v1 = v.split('=', 2) ; $opts[:macros][v0] = v1 }
  opt.on('--cstring', 'encode output as a C string') { $opts[:to_string] = :c }
  opt.on('--jsstring', 'encode output as a js string') { $opts[:to_string] = :js }
  opt.on('--string', 'encode output as a string to stdout') { $opts[:to_string] = :inspect }
  opt.on('--varname name', 'the variable name for string output') { |v| $opts[:varname] = v }
  opt.on('-e class', '--exe class', 'use a specific ExeFormat class') { |c| $opts[:execlass] = Metasm.const_get(c) }
  opt.on('--cpu cpu', 'use a specific CPU class') { |c| $opts[:cpu] = Metasm.const_get(c).new }
  # must come after --cpu in commandline
  opt.on('--16', 'set cpu in 16bit mode') { $opts[:cpu].size = 16 }
  opt.on('--le', 'set cpu in little-endian mode') { $opts[:cpu].endianness = :little }
  opt.on('--be', 'set cpu in big-endian mode') { $opts[:cpu].endianness = :big }
  opt.on('--fno-pic', 'generate position-dependant code') { $opts[:cpu].generate_PIC = false }
  opt.on('--shared', '--lib', '--dll', 'generate shared library') { $opts[:exetype] = :lib }
  opt.on('--ruby-module-hack', 'use the dynldr module hack to use any ruby lib available for ruby symbols') { $opts[:dldrhack] = true }
}.parse!

src = $opts[:macros].map { |k, v| "#define #{k} #{v}\n" }.join

if file = ARGV.shift
  $opts[:srctype] ||= 'c' if file =~ /\.c$/
  if file == '-'
    src << $stdin.read
  else
    src << File.read(file)
  end
else
  $opts[:srctype] ||= $opts[:srctype_data]
  src << DATA.read	# the text after __END__ in this file
end

if $opts[:outfilename] and $opts[:nooverwrite_outfile] and File.exist?($opts[:outfilename])
    abort "Error: target file exists !"
end

if $opts[:srctype] == 'c'
  exe = $opts[:execlass].compile_c($opts[:cpu], src, file)
else
  exe = $opts[:execlass].assemble($opts[:cpu], src, file)
end

if $opts[:to_string]
  str = exe.encode_string

  $opts[:varname] ||= File.basename(file.to_s)[/^\w+/] || 'sc'	# derive varname from filename
  case $opts[:to_string]
  when :inspect
    str = "#{$opts[:varname]} = #{str.inspect}"
  when :c
    str = ["unsigned char #{$opts[:varname]}[#{str.length}] = "] + str.scan(/.{1,19}/m).map { |l|
      '"' + l.unpack('C*').map { |c| '\\x%02x' % c }.join + '"'
    }
    str.last << ?;
  when :js
    str << 0 if str.length & 1 != 0
    str = ["#{$opts[:varname]} = "] + str.scan(/.{2,20}/m).map { |l|
      '"' + l.unpack($opts[:cpu].endianness == :little ? 'v*' : 'n*').map { |c| '%%u%04x' % c }.join + '"+'
    }
    str.last[-1] = ?;
  end

  if of = $opts[:outfilename]
    abort "Error: target file #{of.inspect} exists !" if File.exists?(of) and $opts[:nooverwrite_outfile]
    File.open(of, 'w') { |fd| fd.puts str }
    puts "saved to file #{of.inspect}"
  else
    puts str
  end
else
  of = $opts[:outfilename] ||= 'a.out'
  abort "Error: target file #{of.inspect} exists !" if File.exists?(of) and $opts[:nooverwrite_outfile]
  Metasm::DynLdr.compile_binary_module_hack(exe) if $opts[:dldrhack]
  exe.encode_file(of, $opts[:exetype])
  puts "saved to file #{of.inspect}"
end

__END__
#include <asm/unistd.h>
jmp getip
gotip:
mov eax, __NR_write
mov ebx, 1
pop ecx
mov edx, strend-str
int 80h

mov eax, __NR_exit
mov ebx, 1
int 80h

getip:
call gotip

str db "Hello, world!", 0xa
strend:
