#!/bin/sh
export BASE=`dirname $0`
export PATH=${BASE}/bin:$PATH
export LD_LIBRARY_PATH=${BASE}/lib:$LD_LIBRARY_PATH
$@
