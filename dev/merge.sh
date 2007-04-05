#!/bin/sh

export DEV=/msf3/
export SBL=/projects/metasploit/framework3/tags/framework-3.0/
export FIL=$1

echo "[*] Gathering svn information..."
TMP=`tempfile mergeXXXXXXX`
svn log --limit 1 "${DEV}${FIL}" > $TMP

echo "[*] Copying file ${FIL}..."
cp ${DEV}${FIL} ${SBL}${FIL}

echo "[*] Merging file ${FIL}..."
svn commit --non-interactive -F $TMP ${SBL}${FIL}

rm -f $TMP
