#!/bin/sh

VERSION="3.3.3"

# Grab a fresh copy of Metasploit
if [ -f "tmp/msf3/msfconsole" ]; then
	svn update tmp/msf3/
else
	svn checkout https://www.metasploit.com/svn/framework3/trunk tmp/msf3/
fi
(cd tmp; tar cf msf3.tar msf3)


NAME32="Metasploit Framework v${VERSION} Installer (32-bit)"
PATH32="framework-${VERSION}-linux-i686.run"

NAME64="Metasploit Framework v${VERSION} Installer (64-bit)"
PATH64="framework-${VERSION}-linux-x86_64.run"

rm -rf tmp32
mkdir tmp32
cp tmp/msf3.tar tmp32/
cp bin/linux32.tar.bz2 tmp32/metasploit.tar.bz2
bunzip2 tmp32/metasploit.tar.bz2
cp -a scripts/*.sh tmp32/
cp -a scripts/msfupdate tmp32/
TMP32=tmp32`date +%s1`
mv tmp32 $TMP32
makeself $TMP32 ${PATH32} "${NAME32}" ./installer.sh 32
rm -rf $TMP32

rm -rf tmp64
mkdir tmp64
cp tmp/msf3.tar tmp64/
cp bin/linux64.tar.bz2 tmp64/metasploit.tar.bz2
bunzip2 tmp64/metasploit.tar.bz2
cp -a scripts/*.sh tmp64/
cp -a scripts/msfupdate tmp64/
TMP64=tmp32`date +%s1`
mv tmp64 $TMP64
makeself $TMP64 ${PATH64} "${NAME64}" ./installer.sh 64
rm -rf $TMP64

