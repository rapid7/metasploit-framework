#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# 
# this exemple illustrates the use of the cparser/preprocessor #factorize functionnality:
# it generates code that references to the functions imported by a windows executable, and
# factorizes the windows headers through them
# usage: factorize-imports.rb <exe> <path to visual studio installation> [<additional func names>...]
#

require 'metasm'
include Metasm


ddk = ARGV.delete('--ddk') ? 1 : 0

pe = PE.decode_file_header(ARGV.shift)
pe.decode_imports
funcnames = pe.imports.map { |id| id.imports.map { |i| i.name } }.flatten.compact.uniq.sort

raise 'need a path to the headers' if not visualstudiopath = ARGV.shift

ARGV.each { |n|
	if n[0] == ?-
		funcnames.delete n[1..-1]
	else
		funcnames |= [n]
	end
}

src = <<EOS
// add the path to the visual studio std headers
#define DDK #{ddk}
#ifdef __METASM__
 #if DDK
  #pragma include_dir #{visualstudiopath.inspect}
 #else
  #pragma include_dir #{(visualstudiopath+'/VC/platformsdk/include').inspect}
  #pragma include_dir #{(visualstudiopath+'/VC/include').inspect}
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

void *fnptr[] = { #{funcnames.map { |f| '&'+f }.join(', ')} };
EOS

puts src if $DEBUG
puts Ia32.new.new_cparser.factorize(src)
