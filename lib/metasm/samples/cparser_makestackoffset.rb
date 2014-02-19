#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


#
# This script takes a C header or a path to a Visual Studio install and
# outputs a ruby source file defining StackOffsets, a hash used by the disassembler
# In verbose mode (ruby -v), instead dumps the parsed header (+ warnings)
#

require 'metasm'

filename = ARGV.shift
abort "usage: #$0 filename" if not File.exist? filename

# path to visual studio install directory
if File.directory? filename
	src = <<EOS
// add the path to the visual studio std headers
#ifdef __METASM__
 #pragma include_dir #{(filename+'/VC/platformsdk/include').inspect}
 #pragma include_dir #{(filename+'/VC/include').inspect}
 #pragma prepare_visualstudio
 #pragma no_warn_redefinition
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
EOS
else
	# standalone header
	src = File.read(filename)
end

include Metasm

cp = Ia32.new.new_cparser.parse(src)

if not $VERBOSE
funcs = cp.toplevel.symbol.values.grep(C::Variable).reject { |v| v.initializer or not v.type.kind_of? C::Function }

puts 'module Metasm'
puts 'StackOffsets = {'
align = lambda { |val| (val + cp.typesize[:ptr] - 1) / cp.typesize[:ptr] * cp.typesize[:ptr] }
puts funcs.find_all { |f| f.attributes and f.attributes.include? 'stdcall' and f.type.args }.sort_by { |f| f.name }.map { |f|
	"#{f.name.inspect} => #{f.type.args.inject(0) { |sum, arg| sum + align[cp.sizeof(arg)] }}"
}.join(",\n")
puts '}'
puts 'end'
else
	# dump the full parsed header
	puts cp.lexer.dump_macros(cp.lexer.definition.keys, false), '', '', cp
end
