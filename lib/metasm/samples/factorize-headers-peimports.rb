#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

#
# this exemple illustrates the use of the cparser/preprocessor #factorize functionnality:
# it generates code that references to the functions imported by a windows executable, and
# factorizes the windows headers through them
# usage: factorize-imports.rb <exe> <path to visual studio installation> [<additional func names>... !<func to exclude>]
#

require 'metasm'
include Metasm

require 'optparse'
opts = {}
OptionParser.new { |opt|
	opt.on('--ddk') { opts[:ddk] = true }
	opt.on('-o outfile') { |f| opts[:outfile] = f }
	opt.on('-I additional_header') { |f| (opts[:add_hdrs] ||= []) << f }
	opt.on('--exe executable', '--pe executable') { |f| opts[:pe] = f }
	opt.on('--vs path', '--vspath path') { |f| opts[:vspath] = f }
}.parse!(ARGV)

pe = PE.decode_file_header(opts[:pe] || ARGV.shift)
opts[:vspath] ||= ARGV.shift
raise 'need a path to the headers' if not opts[:vspath]

opts[:vspath].chop! if opts[:vspath][-1] == '/'
opts[:vspath] = opts[:vspath][0...-3] if opts[:vspath][-3..-1] == '/VC'

pe.decode_imports
funcnames = pe.imports.map { |id| id.imports.map { |i| i.name } }.flatten.compact.uniq.sort

ARGV.each { |n|
	if n[0] == ?!
		funcnames.delete n[1..-1]
	else
		funcnames |= [n]
	end
}

src = <<EOS + opts[:add_hdrs].to_a.map { |h| "#include <#{h}>\n" }.join
#define DDK #{opts[:ddk] ? 1 : 0}
#ifdef __METASM__
 #if DDK
  #pragma include_dir #{opts[:vspath].inspect}
 #else
  #pragma include_dir #{(opts[:vspath]+'/VC/platformsdk/include').inspect}
  #pragma include_dir #{(opts[:vspath]+'/VC/include').inspect}
 #endif
 #pragma prepare_visualstudio
 #pragma no_warn_redefinition
 #define _WIN32_WINNT 0x0600	// vista
#endif

#if DDK
 #define NO_INTERLOCKED_INTRINSICS
 typedef struct _CONTEXT CONTEXT;	// needed by ntddk.h, but this will pollute the factorized output..
 typedef CONTEXT *PCONTEXT;
 #define dllimport stdcall		// wtff
 #include <ntddk.h>
 #include <stdio.h>
#else
 #define WIN32_LEAN_AND_MEAN
 #include <windows.h>
 #include <winternl.h>
#endif
EOS

parser = Ia32.new.new_cparser
parser.factorize_init
parser.parse src

# delete imports not present in the header files
funcnames.delete_if { |f|
	if not parser.toplevel.symbol[f]
		puts "// #{f.inspect} is not defined in the headers"
		true
	end
}

parser.parse 'void *fnptr[] = { ' + funcnames.map { |f| '&'+f }.join(', ') + ' };'

outfd = (opts[:outfile] ? File.open(opts[:outfile], 'w') : $stdout)
outfd.puts parser.factorize_final
outfd.close
