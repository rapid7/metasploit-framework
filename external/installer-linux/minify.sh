#!/bin/sh

if [ -z "$1" ]; then
    echo "Need a directory to minify"
    exit 1
fi
MSF_PATH=$1
MINI_PATH=$(dirname "${MSF_PATH}")/msf3-mini
echo $MINI_PATH

# This gets rid of all our .svn files
svn export ${MSF_PATH} ${MINI_PATH}

MINI_EXCLUDES="
HACKING
data/templates/src/
documentation/
external/
lib/msf/ui/gtk2
lib/msf/ui/gtk2.rb
lib/msf/ui/web
lib/msf/ui/web.rb
lib/rex/exploitation/opcodedb.rb
modules/auxiliary/dos/
modules/auxiliary/fuzzers/
msfcli
msfd
msfelfscan
msfgui
msfmachscan
msfopcode
msfpescan
msfrpc
msfrpcd
test
test/
$(find $MINI_PATH -name '*.rb.ut.rb')
"

# If we don't want to blow away the svn files necessary for performing an
# update, we should exclude directories so they don't get re-added when the
# first update happens.  This only works with svn client versions >= 1.5.
#for file in ${MINI_EXCLUDES}; do
#    if [ -d "${MSF_PATH}/${file}" ]; then
#        svn up --set-depth=exclude "${MSF_PATH}/$file"
#    fi
#done
cd ${MINI_PATH}
rm -rf ${MINI_EXCLUDES}

