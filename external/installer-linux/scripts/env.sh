#!/bin/sh
export BASE=`dirname $0`
export PATH=${BASE}/bin:$PATH
export LD_LIBRARY_PATH=${BASE}/lib:$LD_LIBRARY_PATH
unset GEM_PATH
unset MY_RUBY_HOME
unset RUBY_VERSION
unset RUBY_OPTS

$@

