#!/bin/bash

confirm(){
	Q=$1
	while true; do
		echo -n "${Q} (yes/no) > "
		read INPUT

		if [ -z $INPUT ]; then
			exit 1
		fi

		if [ $INPUT == "no" ]; then
			return
		fi

		if [ $INPUT == "yes" ]; then
			return 1
		fi
	done
}

cat banner.sh

if [ `id -u -n` != "root" ]; then
	echo "Error: The installer must be executed as the root user."
	echo ""
	exit 1
fi

if [ -d "/opt/metasploit3" ]; then
	echo "Warning: A copy of Metasploit already exists at /opt/metasploit3"
	echo "         continuing this installation will DELETE the previous  "
	echo "         install, including all user-modified files."
	echo ""
	echo "Please enter 'yes' to continue or any other key to abort"
	confirm "Continue"
	if [ $? -eq "0" ]; then exit; fi
echo ""
fi

echo "This installer will place Metasploit into the /opt/metasploit3 directory."
confirm "Continue"
if [ $? -eq "0" ]; then exit; fi

if [ -d "/opt/metasploit3" ]; then
	echo "Removing files from the previous installation..."
	rm -rf /opt/metasploit3
	find /usr/local/bin -name 'msf*' -type l | xargs rm -f
	echo ""
fi

mkdir -p /opt/metasploit3
echo "Extracting the Metasploit operating environment..."
tar --directory=/opt -xf metasploit.tar
cp run.sh env.sh /opt/metasploit3/
cp msfupdate /opt/metasploit3/app/
echo ""

echo "Extracting the Metasploit Framework..."
tar --directory=/opt/metasploit3 -xf msf3.tar
echo ""

echo "Installing links into /usr/local/bin..."
mkdir -p /usr/local/bin
ln -sf /opt/metasploit3/bin/msf* /usr/local/bin/
echo ""
hash -r

echo "Installation complete."
echo ""

echo "Would you like to automatically update Metasploit?"
confirm "AutoUpdate?"
if [ $? -eq "1" ]; then
	CRON=`mktemp cronXXXXXX`
	crontab -l 2>/dev/null | grep -v msfupdate > $CRON
	echo "30 * * * * /opt/metasploit3/bin/msfupdate > /var/log/msfupdate.log 2>&1" >> $CRON
	crontab $CRON
	rm -f $CRON
	echo ""
else
	echo ""
	echo "Warning: Automatic updates are disabled, update manually with:"
	echo "$ sudo msfupdate"
	echo ""
fi

echo "Would you like to update Metasploit right now?"
confirm "Update?"
if [ $? -eq "1" ]; then
	echo ""
	/opt/metasploit3/bin/msfupdate
	echo ""
fi

echo "Launch the Metasploit console by running 'msfconsole'"
echo ""
echo "Exiting the installer..."

