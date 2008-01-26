#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# 
# this exemple illustrates the use of the cparser/preprocessor #factorize functionnality:
# we write some code using standard headers, and the factorize call on CParser
# gives us back the macro/C definitions that we use in our code, so that we can
# get rid of the header
# Argument: path to visual studio installation
#

require 'metasm'
include Metasm

visualstudiopath = ARGV.shift || '/home/jj/tmp'

# to trace only pp macros (using eg an asm source), use Preprocessor#factorize instead

puts Ia32.new.new_cparser.factorize(<<EOS)
// add the path to the visual studio std headers
#ifdef __METASM__
 #pragma include_dir #{(visualstudiopath+'/VC/platformsdk/include').inspect}
 #pragma include_dir #{(visualstudiopath+'/VC/include').inspect}
 #pragma prepare_visualstudio
 #pragma no_warn_redefinition
#endif

#define WIN32_LEAN_AND_MEAN	// without this, you'll need lots of ram
#include <windows.h>

// now write our code, using preprocessor macros and header-defined variables/types
void *fnptr[] = { GetProcAddress, LoadLibrary, AdjustTokenPrivileges };
int constants[] = { PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE, PAGE_EXECUTE_READ,
	PAGE_EXECUTE_READWRITE, MEM_COMMIT, MEM_RESERVE };
EXCEPTION_RECORD dummy;
EOS

