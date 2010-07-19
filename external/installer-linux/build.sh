#!/bin/sh

VERSION="3.4.1-release"
BASE=`dirname $0`

ARCHIVE=$1
if [ -n "${ARCHIVE}" ]; then
    echo "Extracting archive"
    rm -rf tmp/msf3-*
    tar -C tmp -xjf "${ARCHIVE}"
    cp -r tmp/msf3-http tmp/msf3-full
fi

#
# Expects tmp/msf3.tar to exist and contain a single directory called msf3
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

# Remove any lingering symlinks from previous builds
rm tmp/msf3

(cd tmp; ln -sf msf3-full msf3; tar hcf msf3.tar msf3)

TITLE="Metasploit Framework v${VERSION} Installer (64-bit)"
INSTALLER_FILENAME="framework-${VERSION}-linux-x86_64.run"
BINPATH="${BASE}/bin/linux64.tar.bz2"
if [ -f ${BINPATH} ]; then
    echo "Making 64-bit"
    build_makeself "${TITLE}" "${INSTALLER_FILENAME}" "${BINPATH}"
fi

TITLE="Metasploit Framework v${VERSION} Installer (32-bit)"
INSTALLER_FILENAME="framework-${VERSION}-linux-i686.run"
BINPATH="${BASE}/bin/linux32.tar.bz2"
if [ -f ${BINPATH} ]; then
    echo "Making 32-bit"
    # Build the regular 32-bit installer
    # Uses the same msf3.tar as 64-bit, so we don't need to regenerate it.
    build_makeself "${TITLE}" "${INSTALLER_FILENAME}" "${BINPATH}"

    if [ ! -d tmp/msf3-mini ]; then
        ./minify.sh tmp/msf3-full
    fi

    rm tmp/msf3
    (cd tmp; ln -sf msf3-mini msf3; tar hcf msf3.tar msf3)

    TITLE="Metasploit Framework v${VERSION} Miniature Installer (32-bit)"
    INSTALLER_FILENAME="framework-${VERSION}-mini-linux-i686.run"
    BINPATH="${BASE}/bin/linux32.tar.bz2"
    build_makeself "${TITLE}" "${INSTALLER_FILENAME}" "${BINPATH}"
fi


