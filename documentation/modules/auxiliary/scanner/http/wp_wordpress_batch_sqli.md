## Vulnerable Application

WordPress versions 6.8.0 through 6.8.5, 6.9.0 through 6.9.4, and 7.0.0 through 7.0.1
are vulnerable to:

- **CVE-2026-63030**: REST API Batch Route Confusion — nested batch requests bypass
  authentication context via invalid primer path.
- **CVE-2026-60137**: Blind SQL Injection via the `author__not_in` / `author_exclude`
  parameter.

This scanner performs non-destructive detection:

1. Fingerprints WordPress version from generator meta tag, RSS feed, or REST API
2. Checks if the version falls in the affected range
3. Tests whether the batch route (`/batch/v1`) is accessible
4. Optionally confirms blind SQLi with a time-based differential probe

Fixed in WordPress 6.8.6, 6.9.5, and 7.0.2.

### Setup

```
git clone https://github.com/M4xSec/wp2shell-lab.git
cd wp2shell-lab/lab
docker compose up -d --build
```

WordPress 6.9.0 on `http://localhost:8888`.

## Verification Steps

1. Start msfconsole
2. `use auxiliary/scanner/http/wp_wordpress_batch_sqli`
3. `set RHOSTS <target>`
4. `set RPORT <port>`
5. `set SSL false` (for local lab)
6. `set VHOST <hostname>`
7. `set CONFIRM_SQLI true` (optional, slower but definitive)
8. `run`

## Options

### TARGETURI
WordPress base path. Default: `/`

### TARGET_FILE
Path to a file containing one domain or IP per line. When set, the module
iterates each line, resolves DNS, sets VHOST automatically, and scans. Lines
starting with `#` are skipped. Useful for bulk scanning shared hosting or
Cloudflare-fronted sites.

### CONFIRM_SQLI
When true, sends a `SLEEP()` timing probe through the batch route confusion
chain to definitively confirm the blind SQLi. When false, only checks version
and batch route accessibility. Default: `false`

### SLEEP_TIME
Seconds for the `SLEEP()` call in the SQLi confirmation probe. Default: `3.0`

### WAF_BYPASS
Enable WAF bypass techniques: colon primer path, `/wp-json/` permalink routing,
JSON unicode escaping of SQL keywords, and Origin/Referer headers. Required for
targets behind Cloudflare or similar WAFs that inspect JSON request bodies.
Default: `false`

## Scenarios

### Single target scan (version + batch route only)

```
msf6 > use auxiliary/scanner/http/wp_wordpress_batch_sqli
msf6 auxiliary(scanner/http/wp_wordpress_batch_sqli) > set RHOSTS 127.0.0.1
msf6 auxiliary(scanner/http/wp_wordpress_batch_sqli) > set RPORT 8888
msf6 auxiliary(scanner/http/wp_wordpress_batch_sqli) > set SSL false
msf6 auxiliary(scanner/http/wp_wordpress_batch_sqli) > set VHOST localhost
msf6 auxiliary(scanner/http/wp_wordpress_batch_sqli) > run

[+] localhost — WP 6.9.0 — VULNERABLE (RCE, CVE-2026-63030) — batch route open
[*] Auxiliary module execution completed
```

### Single target with SQLi confirmation

```
msf6 auxiliary(scanner/http/wp_wordpress_batch_sqli) > set CONFIRM_SQLI true
msf6 auxiliary(scanner/http/wp_wordpress_batch_sqli) > run

[*]   localhost — SQLi probe: fast=0.045s slow=3.038s delta=2.993s
[+] localhost — WP 6.9.0 — VULNERABLE (RCE, CVE-2026-63030) — SQLi CONFIRMED
[*] Auxiliary module execution completed
```

### Bulk scan from file

```
msf6 auxiliary(scanner/http/wp_wordpress_batch_sqli) > set TARGET_FILE /tmp/wp-targets.txt
msf6 auxiliary(scanner/http/wp_wordpress_batch_sqli) > set CONFIRM_SQLI false
msf6 auxiliary(scanner/http/wp_wordpress_batch_sqli) > run

[*] Scanning 3 target(s) from /tmp/wp-targets.txt...

[+] example.com — WP 6.9.2 — VULNERABLE (RCE, CVE-2026-63030) — batch route open
[*] blog.example.org — WordPress 7.0.2 — not affected
[!] store.example.net — WP 6.9.0 — affected (RCE) but batch route returned 403
[*] Scan complete: 3 target(s)
```

### WAF bypass scan (Cloudflare/ModSecurity)

```
msf6 auxiliary(scanner/http/wp_wordpress_batch_sqli) > set RHOSTS 127.0.0.1
msf6 auxiliary(scanner/http/wp_wordpress_batch_sqli) > set RPORT 9999
msf6 auxiliary(scanner/http/wp_wordpress_batch_sqli) > set VHOST localhost
msf6 auxiliary(scanner/http/wp_wordpress_batch_sqli) > set WAF_BYPASS true
msf6 auxiliary(scanner/http/wp_wordpress_batch_sqli) > set CONFIRM_SQLI true
msf6 auxiliary(scanner/http/wp_wordpress_batch_sqli) > run

[*]   localhost — SQLi probe: fast=0.052s slow=3.047s delta=2.995s
[+] localhost — WP 6.9.0 — VULNERABLE (RCE, CVE-2026-63030) — SQLi CONFIRMED
[*] Auxiliary module execution completed
```
