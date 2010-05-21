#!/bin/sh

VERSION="3.4.0-release"
BASE=`dirname $0`

# Grab a fresh copy of Metasploit
if [ -f "tmp/msf3/msfconsole" ]; then
	svn update tmp/msf3/
else
	svn checkout https://www.metasploit.com/svn/framework3/trunk tmp/msf3/
fi
(cd tmp; tar cf msf3.tar msf3)

build_makeself() {
    NAME=$1
    INSTALLER_FILENAME=$2
    BIN_TARBALL_PATH=$3

    TMP=tmp_install_`date +%s1`
    mkdir ${TMP}/
    cp tmp/msf3.tar ${TMP}/
    cp ${BIN_TARBALL_PATH} ${TMP}/metasploit.tar.bz2
    bunzip2 ${TMP}/metasploit.tar.bz2
    cp -a scripts/*.sh ${TMP}/
    cp -a scripts/msfupdate ${TMP}/
    makeself "${TMP}" "${INSTALLER_FILENAME}" "${NAME}" ./installer.sh
    rm -rf ${TMP}
}

NAME32="Metasploit Framework v${VERSION} Installer (32-bit)"
PATH32="framework-${VERSION}-linux-i686.run"
BINPATH32="${BASE}/bin/linux32.tar.bz2"
build_makeself "${NAME32}" "${PATH32}" "${BINPATH32}"

NAME64="Metasploit Framework v${VERSION} Installer (64-bit)"
PATH64="framework-${VERSION}-linux-x86_64.run"
BINPATH64="${BASE}/bin/linux64.tar.bz2"
build_makeself "${NAME64}" "${PATH64}" "${BINPATH64}"

