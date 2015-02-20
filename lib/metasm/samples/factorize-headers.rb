#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

#
# this exemple illustrates the use of the cparser/preprocessor #factorize functionnality:
# we write some code using standard headers, and the factorize call on CParser
# gives us back the macro/C definitions that we use in our code, so that we can
# get rid of the header
# Argument: C file to factorize, [path to visual studio installation]
# with a single argument, uses GCC standard headers
#

require 'metasm'
include Metasm

abort 'target needed' if not file = ARGV.shift

visualstudiopath = ARGV.shift
if visualstudiopath
  stub = <<EOS
// add the path to the visual studio std headers
#ifdef __METASM__
 #pragma include_dir #{(visualstudiopath+'/platformsdk/include').inspect}
 #pragma include_dir #{(visualstudiopath+'/include').inspect}
 #pragma prepare_visualstudio
 #pragma no_warn_redefinition
#endif
EOS
else
  stub = <<EOS
#ifdef __METASM__
 #pragma prepare_gcc
#endif
EOS
end
stub << "#line 0\n"

# to trace only pp macros (using eg an asm source), use Preprocessor#factorize instead

puts Ia32.new.new_cparser.factorize(stub + File.read(file), file)

