#!/bin/bash

# Requires bash version 3 or so for regular expression pattern match

COMMITTER_KEYS_URL='https://raw.githubusercontent.com/wiki/rapid7/metasploit-framework/Committer-Keys.md'
KEYBASE_KEY_URLS=$(
 \curl -sSL $COMMITTER_KEYS_URL |
 \awk '$4 ~/https:\/\/keybase.io\//' |
 \sed 's#.*\(https://keybase.io/[^)]*\).*#\1/key.asc#'
)

for key in $KEYBASE_KEY_URLS; do
  echo Importing $key...
  \curl -sSL $key | gpg --quiet --no-auto-check-trustdb --import -
done

# Exceptions -- keys that do show up in the logs, but aren't (yet) in Keybase:
# This should cover every key since May of 2014.

# Currently, one lone missing key:
#
# gpg: Signature made Mon 16 Feb 2015 02:09:53 PM CST using RSA key ID D5D50A02
# gpg: Can't check signature: public key not found
# 14da69c - Land #4757, adds RC for auto payload gen (3 months ago) <kernelsmith@github> []
#
# https://github.com/rapid7/metasploit-framework/commit/14da69c is
# harmless, though. It's only an RC script, not run by default, and it
# automates setting up a payload handler.


echo Processing exceptions...

MIT_KEYIDS="
Brandont       0xA3EE1B07
Ccatalan       0xC3953653
Farias         0x01DF79A1
Firefart       0x66BC32C7
HDM            0xFA604913
Jvennix        0x3E85A2B0
Kernelsmith    0x3D609E33
Lsanchez       0xFB80E8DD
OJ             0x1FAA5749
Sgonzalez      0xCA93BCE5
Shuckins       0x8C03C944
TheLightCosine 0x3A913DB2
Wvu            0xC1629024
"

MIT_KEY_URL_BASE="https://pgp.mit.edu/pks/lookup?op=get&search="

for key in $MIT_KEYIDS; do
  if [[ $key =~ ^0x ]]
  then
    \curl -sSL $MIT_KEY_URL_BASE$key | gpg --quiet --no-auto-check-trustdb --import -
  else
    echo Importing key for $key...
  fi
done

