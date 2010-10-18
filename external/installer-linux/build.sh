#!/bin/sh

VERSION="3.5.0-beta"
BASE=`dirname $0`

usage() {
    echo "MSF Installer Builder"
    echo "Options:"
    echo "  -h                 This help message."
    echo "  -a <archive>       A tar.bz2 archive of msf3. This should be an http repository"
    echo "                     checked out with an old version of svn (usually 1.3.1) for"
    echo "                     compatibility reasons.  Note that this will rm any existing"
    echo "                     msf3-* directory."
    echo "  -v <version name>  The version name of this release, usually as found in"
    echo "                     lib/msf/core/framework.rb or something like "
    echo "                     3.4-nightly-\`date +%F\` for nightlies."
    echo "                     Defaults to ${VERSION}."
    exit 1
}

while getopts ":a:hv:" flag; do
    case $flag in
        a)
            echo archive=$OPTARG
            [ -z "$OPTARG" ] && exit 1
            ARCHIVE=$OPTARG
            shift $(($OPTIND - 1)); OPTIND=1
            ;;
        v)
            echo version=$OPTARG
            [ -z "$OPTARG" ] && exit 1
            VERSION=$OPTARG
            shift $(($OPTIND - 1)); OPTIND=1
            ;;
        h)
            usage
            ;;
        :) echo Missing argument to $OPTARG
            usage
            ;;
        *) echo unknown opt $flag
    esac
done

echo Building installers for Metasploit Framework v${VERSION}

if [ -n "${ARCHIVE}" ]; then
    echo "Extracting archive"
    rm -rf msf3-*
    tar -xjf "${ARCHIVE}"
    if [ ! -d msf3-http ]; then
        echo "${ARCHIVE} must contain an svn checkout of msf as a single directory called msf3-http"
        exit 1
    fi
fi

if [ -z "$(which makeself)" ]; then
    echo "makeself needs to be installed and in the path"
    exit 2
fi

if [ ! -d msf3-http ]; then
    echo "Cannot continue without an svn checkout of msf called msf3-http"
    exit 3
fi

#
# Expects msf3.tar to exist and contain a single directory called msf3
#
build_makeself() {
    TITLE=$1
    INSTALLER_FILENAME=$2
    BIN_TARBALL_PATH=$3

    TMP=tmp_install_`date +%s1`
    mkdir ${TMP}/
    cp msf3.tar ${TMP}/
    cp ${BIN_TARBALL_PATH} ${TMP}/metasploit.tar.bz2
    bunzip2 ${TMP}/metasploit.tar.bz2
    cp -a ${BASE}/scripts/*.sh ${TMP}/
    cp -a ${BASE}/scripts/msfupdate ${TMP}/
    makeself "${TMP}" "${INSTALLER_FILENAME}" "${TITLE}" ./installer.sh
    rm -rf ${TMP}
}

# Remove any lingering symlinks from previous builds
rm msf3 2>/dev/null

ln -sf msf3-http msf3
tar hcf msf3.tar msf3
ln -sf msf3-http framework-${VERSION}
tar jhcf framework-${VERSION}.tar.bz2 framework-${VERSION}
rm framework-${VERSION}

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

    ${BASE}/minify.sh msf3-http

    rm msf3 msf3.tar
    ln -sf msf3-mini msf3
    tar hcf msf3.tar msf3

    TITLE="Metasploit Framework v${VERSION} Miniature Installer (32-bit)"
    INSTALLER_FILENAME="framework-${VERSION}-mini-linux-i686.run"
    BINPATH="${BASE}/bin/linux32.tar.bz2"
    build_makeself "${TITLE}" "${INSTALLER_FILENAME}" "${BINPATH}"
fi

rm msf3 msf3.tar

