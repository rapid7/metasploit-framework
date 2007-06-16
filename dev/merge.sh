#!/bin/sh

export DEV=/home/mmiller/svn/framework3/trunk/
export SBL=/home/mmiller/svn/framework3/tags/framework-3.0/
export FIL=$1

echo "[*] Gathering svn information..."
TMP=`tempfile mergeXXXXXXX`
svn log --limit 1  "${DEV}${FIL}" | egrep -v '^r[0-9]+|^--|^$' > $TMP

echo "[*] Copying file ${FIL}..."
cp ${DEV}${FIL} ${SBL}${FIL}

echo "[*] Merging file ${FIL}..."
svn add ${SBL}${FIL} >/dev/null 2>&1
svn commit --non-interactive -F $TMP ${SBL}${FIL}

rm -f $TMP
