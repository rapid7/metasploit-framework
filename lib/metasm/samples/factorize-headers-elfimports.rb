#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

#
# this exemple illustrates the use of the cparser/preprocessor #factorize functionnality:
# it generates code that references to the functions imported by an ELF executable
# usage: factorize-imports.rb <exe> [<path to include dir>] [<additional func names>... !<func to exclude>]
#

require 'metasm'
include Metasm

require 'optparse'
opts = { :hdrs => [], :defs => {}, :path => [] }
OptionParser.new { |opt|
	opt.on('-o outfile') { |f| opts[:outfile] = f }
	opt.on('-H additional_header') { |f| opts[:hdrs] << f }
	opt.on('--exe executable') { |f| opts[:exe] = f }
	opt.on('-I path', '--includepath path') { |f| opts[:path] << f }
	opt.on('-D var') { |f| k, v = f.split('=', 2) ; opts[:defs].update k => (v || '') }
	opt.on('--gcc') { opts[:gcc] = true }
	opt.on('--vs', '--visualstudio') { opts[:vs] = true }
}.parse!(ARGV)

exe = AutoExe.decode_file_header(opts[:exe] || ARGV.shift)
opts[:path] ||= [ARGV.shift] if not ARGV.empty?

case exe
when PE
	exe.decode_imports
	funcnames = exe.imports.map { |id| id.imports.map { |i| i.name } }
when ELF
	exe.decode_segments_dynamic
	funcnames = exe.symbols.map { |s| s.name if s.shndx == 'UNDEF' and s.type == 'FUNC' }
	opts[:hdrs] << 'stdio.h' << 'stdlib.h' << 'unistd.h'
	opts[:gcc] = true if not opts[:vs]
else raise "unsupported #{exe.class}"
end

funcnames = funcnames.flatten.compact.uniq.sort

ARGV.each { |n|
	if n[0] == ?!
		funcnames.delete n[1..-1]
	else
		funcnames |= [n]
	end
}

src = <<EOS
#ifdef __METASM__
#{opts[:path].map { |i| ' #pragma include_dir ' + i.inspect }.join("\n")}
#{'#pragma prepare_visualstudio' if opts[:vs]}
#{'#pragma prepare_gcc' if opts[:gcc]}
#pragma no_warn_redefinition
#endif

#{opts[:defs].map { |k, v| "#define #{k} #{v}" }.join("\n")}
#{opts[:hdrs].map { |h| "#include <#{h}>" }.join("\n")}
EOS

parser = Ia32.new.new_cparser
parser.factorize_init
parser.parse src

outfd = (opts[:outfile] ? File.open(opts[:outfile], 'w') : $stdout)

# delete imports not present in the header files
funcnames.delete_if { |f|
	if not parser.toplevel.symbol[f]
		puts "// #{f.inspect} is not defined in the headers"
		true
	end
}

parser.parse "void *fnptr[] = { #{funcnames.map { |f| '&'+f }.join(', ')} };"

outfd.puts parser.factorize_final
outfd.close
