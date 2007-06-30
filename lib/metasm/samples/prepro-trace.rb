#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# 
# this exemple illustrates the use of the trace_macro functionnality:
# we write some code using macros defined in a header, and the trace_macro
# gives us back the macro definition that we use in our code, so that we can
# get rid of the header
# TODO same thing with C struct/prototypes
#

require 'metasm/preprocessor'
include Metasm
require 'pp'

# traces macro use, returns only the one used (and the one they depend on)
begin
# create a fictive header
File.open('foo.h', 'w') { |fd| fd.puts DATA.read }

p = Preprocessor.new
# macro tracing is done only in files included with <>
p.include_search_path << '.'
# do the trace and print the result
puts p.trace_macros(<<EOS)
#include <foo.h>
#define abc(toto) xxx toto
abc(aaa)
EOS
ensure
# cleanup our header
File.unlink('foo.h')
end

__END__
// header content goes here
#define gugu(zo) (zo+2)
#define x gugu(4)
#define y 2
#define xxx x
#define yyy y
