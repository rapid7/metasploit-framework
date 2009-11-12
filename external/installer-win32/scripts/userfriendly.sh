#!/bin/bash

#
# Reset file permissions to allow other users
#
umask 022
chmod 755 -R /bin /*.bat /lib /usr /var /dev /etc /sbin /msf3 2>/dev/null
if [ $? -ne "0" ]; then
	echo "[*] This application *MUST* be launched as an administrator the first time"
	echo "[*] Press enter to exit"
	read BOOM
	exit 1
fi

chmod 755 /home
chmod 1777 /tmp /var/tmp
touch /etc/_FRIENDLY_
