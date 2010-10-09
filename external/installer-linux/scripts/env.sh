#!/bin/sh
export BASE=`dirname $0`
export PATH="${BASE}/bin":$PATH
export LD_LIBRARY_PATH="${BASE}/lib":$LD_LIBRARY_PATH
export GEM_HOME="${BASE}/lib/ruby/gems/1.9.1/gems/"
export GEM_PATH="${BASE}/lib/ruby/gems/1.9.1/gems/"
unset MY_RUBY_HOME
unset RUBY_VERSION
unset RUBY_OPTS

"$@"

