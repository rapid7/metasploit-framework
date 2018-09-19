#!/bin/bash

MSF_USER=msf
MSF_GROUP=msf
TMP=${MSF_UID:=1000}
TMP=${MSF_GID:=1000}

# don't recreate system users like root
if [ "$MSF_UID" -lt "1000" ]; then
  MSF_UID=1000
fi

if [ "$MSF_GID" -lt "1000" ]; then
  MSF_GID=1000
fi

addgroup -g $MSF_GID $MSF_GROUP
adduser -u $MSF_UID -D $MSF_USER -g $MSF_USER -G $MSF_GROUP $MSF_USER

su-exec $MSF_USER "$@"
