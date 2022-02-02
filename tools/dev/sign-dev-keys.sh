#!/bin/bash

# Imports and signs dev keys fetched from Keybase, as asserted by the
# Metasploit-Framework development wiki. Requires bash version 3 or so for
# regular expression pattern match

COMMITTER_KEYS_URL='https://raw.githubusercontent.com/wiki/rapid7/metasploit-framework/Committer-Keys.md'
KEYBASE_KEY_URLS=$(
 \curl -sSL $COMMITTER_KEYS_URL |
 \awk '$4 ~/https:\/\/keybase.io\//' |
 \sed 's#.*\(https://keybase.io/[^)]*\).*#\1/key.asc#'
)

for key in $KEYBASE_KEY_URLS; do
  echo [*] Importing $key
  THIS_KEY=$(
    \curl -sSL $key |
    \gpg --no-auto-check-trustdb --import - 2>&1 |
    \head -1 | \cut -f 3 -d " " | \sed 's/://'
  )
  echo [*] Signing $THIS_KEY
  \gpg --sign-key $THIS_KEY
  echo [*] Sending $THIS_KEY
  \gpg --keyserver sks-keyservers.net --send-key $THIS_KEY
done

