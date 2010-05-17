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

INSTALL_DIR=/opt/metasploit3

cat banner.sh

if [ `id -u -n` != "root" ]; then
	echo "Error: The installer must be executed as the root user."
	echo ""
	exit 1
fi

if [ -d "${INSTALL_DIR}" ]; then
	echo "Warning: A copy of Metasploit already exists at ${INSTALL_DIR}"
	echo "         continuing this installation will DELETE the previous  "
	echo "         install, including all user-modified files."
	echo ""
	echo "Please enter 'yes' to continue or any other key to abort"
	confirm "Continue"
	if [ $? -eq "0" ]; then exit; fi
echo ""
fi

echo "This installer will place Metasploit into the ${INSTALL_DIR} directory."
confirm "Continue"
if [ $? -eq "0" ]; then exit; fi

if [ -d "${INSTALL_DIR}" ]; then
	echo "Removing files from the previous installation..."
	rm -rf "${INSTALL_DIR}"
	find /usr/local/bin -name 'msf*' -type l | xargs rm -f
	echo ""
fi

mkdir -p "${INSTALL_DIR}"
echo "Extracting the Metasploit operating environment..."
tar --directory=/opt -xf metasploit.tar
cp run.sh env.sh "${INSTALL_DIR}"/
cp msfupdate "${INSTALL_DIR}"/app/
echo ""

echo "Extracting the Metasploit Framework..."
tar --directory="${INSTALL_DIR}" -xf msf3.tar
echo ""

echo "Installing links into /usr/local/bin..."
mkdir -p /usr/local/bin
ln -sf "${INSTALL_DIR}"/bin/msf* /usr/local/bin/
echo ""
hash -r

echo "Installation complete."
echo ""

echo "Would you like to automatically update Metasploit?"
confirm "AutoUpdate?"
if [ $? -eq "1" ]; then
	CRON=`mktemp cronXXXXXX`
	crontab -l 2>/dev/null | grep -v msfupdate > $CRON
	echo "30 * * * * \"${INSTALL_DIR}\"/bin/msfupdate > /var/log/msfupdate.log 2>&1" >> $CRON
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
	"${INSTALL_DIR}"/bin/msfupdate
	echo ""
fi

echo "Launch the Metasploit console by running 'msfconsole'"
echo ""
echo "Exiting the installer..."

