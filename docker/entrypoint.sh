#!/bin/bash

MSF_USER=msf
MSF_GROUP=msf
TMP=${MSF_UID:=1000}
TMP=${MSF_GID:=1000}

# if the user starts the container as root or another system user,
# don't use a low privileged user as we mount the home directory
if [ "$MSF_UID" -eq "0" ]; then
  "$@"
else
  # if the users group already exists, create a random GID, otherwise
  # reuse it
  if ! grep ":$MSF_GID:" /etc/group > /dev/null; then
    addgroup -g $MSF_GID $MSF_GROUP
  else
    addgroup $MSF_GROUP
  fi

  # check if user id already exists
  if ! grep ":$MSF_UID:" /etc/passwd > /dev/null; then
    adduser -u $MSF_UID -D $MSF_USER -g $MSF_USER -G $MSF_GROUP $MSF_USER
    # add user to metasploit group so it can read the source
    addgroup $MSF_USER $METASPLOIT_GROUP
    su-exec $MSF_USER "$@"
  # fall back to root exec if the user id already exists
  else
    "$@"
  fi
fi
