#!/bin/sh

# Check privileges
if [ $(id -u) != 0 ]; then
    echo "$0 must be run as root, try sudo $0"
    exit
fi

# Check for systemctl
_=$(which systemctl)
if [ $? -eq 0 ]; then
    echo "Stopping hide.me"
    systemctl stop 'hide.me@*'
    echo "Unlinking service files"
    systemctl disable hide.me@.service
fi

echo "Removing hide.me directory"
rm -r /opt/hide.me

echo "hide.me CLI removed"