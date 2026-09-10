## Description

An rsync module is essentially a directory share. These modules can optionally be protected by a password. This module connects to and
negotiates with an rsync server, lists the available modules and, optionally, determines if the module requires a password to access.

## Vulnerable Application

### Kali rolling with rsync 3.4.4 (protocol 32, August 2026)

```
# rsync 3.4.4 / protocol 32 - current Kali rolling package
# (the newest daemon; strict handshake with subprotocol + digest list)
FROM kalilinux/kali-rolling:latest

RUN apt-get update \
    && apt-get install -y --no-install-recommends rsync \
    && rm -rf /var/lib/apt/lists/*

RUN <<'SETUP'
mkdir -p /srv/share
echo 'hello from kali-rolling (rsync 3.4.4, protocol 32)' > /srv/share/file.txt
cat > /etc/rsyncd.secrets <<'SECRETS'
demouser:secretpw
SECRETS
chmod 600 /etc/rsyncd.secrets
cat > /etc/rsyncd.conf <<'CONF'
use chroot = no
reverse lookup = no
forward lookup = no
pid file = /tmp/rsyncd.pid
log file = /tmp/rsyncd.log

[public]
    path = /srv/share
    comment = open share
    read only = yes

[locked]
    path = /srv/share
    comment = password-protected share
    read only = yes
    auth users = demouser
    secrets file = /etc/rsyncd.secrets
CONF
SETUP

EXPOSE 873
CMD ["rsync", "--daemon", "--no-detach", "--config", "/etc/rsyncd.conf"]
```

### Debian 12 with rsync 3.2.7 (protocol 32)

```
# rsync 3.2.7 / protocol 32 - Debian 12 point-release package
# (first protocol-32 daemon; same strict handshake as 3.4.x)
FROM debian:12

RUN apt-get update \
    && apt-get install -y --no-install-recommends rsync \
    && rm -rf /var/lib/apt/lists/*

RUN <<'SETUP'
mkdir -p /srv/share
echo 'hello from debian 12 (rsync 3.2.7, protocol 32)' > /srv/share/file.txt
cat > /etc/rsyncd.secrets <<'SECRETS'
demouser:secretpw
SECRETS
chmod 600 /etc/rsyncd.secrets
cat > /etc/rsyncd.conf <<'CONF'
use chroot = no
reverse lookup = no
forward lookup = no
pid file = /tmp/rsyncd.pid
log file = /tmp/rsyncd.log

[public]
    path = /srv/share
    comment = open share
    read only = yes

[locked]
    path = /srv/share
    comment = password-protected share
    read only = yes
    auth users = demouser
    secrets file = /etc/rsyncd.secrets
CONF
SETUP

EXPOSE 873
CMD ["rsync", "--daemon", "--no-detach", "--config", "/etc/rsyncd.conf"]
```

### Ubuntu 20.04 with rsync 3.1.3 (protocol 31)

```
# rsync 3.1.3 / protocol 31 - Ubuntu 20.04 package
# (old-style handshake: "@RSYNCD: 31.0", no digest list - the regression case)
FROM ubuntu:20.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends rsync \
    && rm -rf /var/lib/apt/lists/*

RUN <<'SETUP'
mkdir -p /srv/share
echo 'hello from ubuntu 20.04 (rsync 3.1.3, protocol 31)' > /srv/share/file.txt
cat > /etc/rsyncd.secrets <<'SECRETS'
demouser:secretpw
SECRETS
chmod 600 /etc/rsyncd.secrets
cat > /etc/rsyncd.conf <<'CONF'
use chroot = no
reverse lookup = no
forward lookup = no
pid file = /tmp/rsyncd.pid
log file = /tmp/rsyncd.log

[public]
    path = /srv/share
    comment = open share
    read only = yes

[locked]
    path = /srv/share
    comment = password-protected share
    read only = yes
    auth users = demouser
    secrets file = /etc/rsyncd.secrets
CONF
SETUP

EXPOSE 873
CMD ["rsync", "--daemon", "--no-detach", "--config", "/etc/rsyncd.conf"]
```

## Verification Steps

  1. Do: `use auxiliary/scanner/rsync/modules_list`
  2. Do: `set rhosts [ips]`
  3. Do: `run`

## Options

### TEST_AUTHENTICATION

  Connect to each share and test if authentication is required.

### VERBOSE

  When set to `false`, each module will be listed.  When set to `true` each module will be listed, then a summary
  table will also be printed including if authentication is required, and any module comments.  `false` is the default value.

## Scenarios

### Kali rolling with rsync 3.4.4  (protocol 32, August 2026)

```
docker build -t kali_rsync .
docker run -p 873:873 kali_rsync
```

```
msf > use auxiliary/scanner/rsync/modules_list
msf auxiliary(scanner/rsync/modules_list) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf auxiliary(scanner/rsync/modules_list) > set verbose true
verbose => true
msf auxiliary(scanner/rsync/modules_list) > set SHOW_MOTD true
SHOW_MOTD => true
msf auxiliary(scanner/rsync/modules_list) > set SHOW_VERSION true
SHOW_VERSION => true
msf auxiliary(scanner/rsync/modules_list) > run
[*] 127.0.0.1:873         - rsync protocol version: 32.0
[+] 127.0.0.1:873         - 2 rsync modules found: public, locked

rsync modules for 127.0.0.1:873        
=======================================

   Name    Comment                   Authentication
   ----    -------                   --------------
   locked  password-protected share  required
   public  open share                not required


[*] 127.0.0.1:873         - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Debian 12 with rsync 3.2.7 (protocol 32)

```
docker build -t debian_rsync .
docker run -p 873:873 debian_rsync
```

```
msf > use auxiliary/scanner/rsync/modules_list
msf auxiliary(scanner/rsync/modules_list) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf auxiliary(scanner/rsync/modules_list) > set verbose true
verbose => true
msf auxiliary(scanner/rsync/modules_list) > set SHOW_MOTD true
SHOW_MOTD => true
msf auxiliary(scanner/rsync/modules_list) > set SHOW_VERSION true
SHOW_VERSION => true
msf auxiliary(scanner/rsync/modules_list) > run
[*] 127.0.0.1:873         - rsync protocol version: 32.0
[+] 127.0.0.1:873         - 2 rsync modules found: public, locked

rsync modules for 127.0.0.1:873        
=======================================

   Name    Comment                   Authentication
   ----    -------                   --------------
   locked  password-protected share  required
   public  open share                not required


[*] 127.0.0.1:873         - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Ubuntu 20.04 with rsync 3.1.3 (protocol 31)

```
docker build -t ubuntu_rsync .
docker run -p 873:873 ubuntu_rsync
```

```
msf > use auxiliary/scanner/rsync/modules_list
msf auxiliary(scanner/rsync/modules_list) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf auxiliary(scanner/rsync/modules_list) > set verbose true
verbose => true
msf auxiliary(scanner/rsync/modules_list) > set SHOW_MOTD true
SHOW_MOTD => true
msf auxiliary(scanner/rsync/modules_list) > set SHOW_VERSION true
SHOW_VERSION => true
msf auxiliary(scanner/rsync/modules_list) > run
[*] 127.0.0.1:873         - rsync protocol version: 31.0
[+] 127.0.0.1:873         - 2 rsync modules found: public, locked

rsync modules for 127.0.0.1:873        
=======================================

   Name    Comment                   Authentication
   ----    -------                   --------------
   locked  password-protected share  required
   public  open share                not required


[*] 127.0.0.1:873         - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

## Confirming

### [nmap](https://nmap.org/nsedoc/scripts/rsync-list-modules.html)

```
# nmap -p 873 -sV -script=rsync-list-modules 10.168.202.216
Starting Nmap 7.70 ( https://nmap.org ) at 2018-07-12 16:32 EDT
Nmap scan report for 10.168.202.216
Host is up (0.000045s latency).

PORT    STATE SERVICE VERSION
873/tcp open  rsync   (protocol version 31)
| rsync-list-modules: 
|   read only files	Files are read only
|   writable       	Files can be written to
|_  authenticated  	Files require authentication

```
