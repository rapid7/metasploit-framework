#!/bin/sh

VERSION="3.4.0-release"
BASE=`dirname $0`

# We can only "exclude" directories.  For specific files, we just have to rm
# them.
MINI_EXCLUDES="
data/templates/src
documentation
external/installer-linux
external/installer-win32
external/source
lib/rex/exploitation/opcodedb.rb
test
"
MINI_RM="
msfd
msfelfscan
msfgui
msfmachscan
msfopcode
msfpescan
msfrpc
msfrpcd
msfweb
test
$(find tmp/msf3-mini -name '*.rb.ut.rb')
"


#
# Expects tmp/msf3.tar to exist
#
build_makeself() {
    TITLE=$1
    INSTALLER_FILENAME=$2
    BIN_TARBALL_PATH=$3

    TMP=tmp_install_`date +%s1`
    mkdir ${TMP}/
    cp tmp/msf3.tar ${TMP}/
    cp ${BIN_TARBALL_PATH} ${TMP}/metasploit.tar.bz2
    bunzip2 ${TMP}/metasploit.tar.bz2
    cp -a scripts/*.sh ${TMP}/
    cp -a scripts/msfupdate ${TMP}/
    makeself "${TMP}" "${INSTALLER_FILENAME}" "${TITLE}" ./installer.sh
    rm -rf ${TMP}
}

if [ -f tmp/msf3/msfconsole ]; then
    svn up tmp/msf3
else
    svn co https://www.metasploit.com/svn/framework3/trunk msf3
fi
if [ -f tmp/msf3-mini/msfconsole ]; then
    svn up tmp/msf3-mini
else
    cp -r tmp/msf3 tmp/msf3-mini
    for dir in ${MINI_EXCLUDES}; do
        # Supposedly only have to do this once
        svn up --set-depth=exclude "$dir" 2>/dev/null
    done
fi
for file in ${MINI_RM}; do
    rm -rf tmp/msf3-mini/"$file"
done


(cd tmp; tar cf msf3.tar msf3)

TITLE="Metasploit Framework v${VERSION} Installer (64-bit)"
INSTALLER_FILENAME="framework-${VERSION}-linux-x86_64.run"
BINPATH="${BASE}/bin/linux64.tar.bz2"
if [ -f ${BINPATH} ]; then
    build_makeself "${TITLE}" "${INSTALLER_FILENAME}" "${BINPATH}"
fi

TITLE="Metasploit Framework v${VERSION} Installer (32-bit)"
INSTALLER_FILENAME="framework-${VERSION}-linux-i686.run"
BINPATH="${BASE}/bin/linux32.tar.bz2"
if [ -f ${BINPATH} ]; then
    # Build the regular 32-bit installer
    # Uses the same msf3.tar as 64-bit, so we don't need to regenerate it.
    build_makeself "${TITLE}" "${INSTALLER_FILENAME}" "${BINPATH}"

    # Set up and build the mini 32-bit installer
    mv tmp/msf3 tmp/msf3-full
    mv tmp/msf3-mini tmp/msf3
    (cd tmp; tar cf msf3.tar msf3)
    mv tmp/msf3 tmp/msf3-mini
    mv tmp/msf3-full tmp/msf3

    TITLE="Metasploit Framework v${VERSION} Miniature Installer (32-bit)"
    INSTALLER_FILENAME="framework-${VERSION}-mini-linux-i686.run"
    BINPATH="${BASE}/bin/linux32.tar.bz2"
    build_makeself "${TITLE}" "${INSTALLER_FILENAME}" "${BINPATH}"
fi


