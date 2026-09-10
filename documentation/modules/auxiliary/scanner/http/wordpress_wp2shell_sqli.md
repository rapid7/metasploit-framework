## Vulnerable Application

WordPress core versions **6.9.0 - 6.9.4** and **7.0.0 - 7.0.1** are affected by an
unauthenticated SQL injection ("wp2shell") reachable through the REST API batch
endpoint (`/batch/v1`). No plugins and no authentication are required.

The batch controller (`serve_batch_request_v1()`) builds two parallel arrays, `$matches`
(the matched handler per sub-request) and `$validation` (the validation result per
sub-request), then indexes both by the same offset when dispatching. A sub-request whose
path fails `wp_parse_url()` is appended to `$validation` but not to `$matches`, so the two
arrays fall out of step and a sub-request is dispatched under a different sub-request's
handler (**CVE-2026-63030**, route confusion).

By nesting the primitive twice, a `GET` on the single-post item route
`/wp/v2/posts/999999` carrying the collection-only parameter `author_exclude` is dispatched
under the posts collection `get_items()` handler, where `author_exclude` maps to the
`WP_Query` `author__not_in` query var. The vulnerable builds interpolate that value into SQL
as a string (**CVE-2026-60137**), producing a pre-authentication boolean- and time-based
blind SQL injection in the `post_author NOT IN (...)` clause.

| Branch | Vulnerable | Fixed |
| ------ | ---------- | ----- |
| 6.8.x | 6.8.0 - 6.8.5 (CVE-2026-60137 SQLi only, no route confusion) | 6.8.6 |
| 6.9.x | 6.9.0 - 6.9.4 | 6.9.5 |
| 7.0.x | 7.0.0 - 7.0.1 | 7.0.2 |

This module targets the complete unauthenticated route-confusion and SQL injection chain,
so it supports WordPress 6.9.0 - 6.9.4 and 7.0.0 - 7.0.1. The 6.8.x branch contains only
the separately gated SQL injection and is not affected by the unauthenticated chain.

### Setting up a test environment

The following `docker-compose.yml` starts a vulnerable WordPress 6.9.4 instance with a
MySQL 8.0 backend on port 8080:

```yaml
services:
  wordpress:
    image: wordpress:6.9.4
    restart: always
    ports:
      - 8080:80
    environment:
      WORDPRESS_DB_HOST: db
      WORDPRESS_DB_USER: wordpress
      WORDPRESS_DB_PASSWORD: wordpress
      WORDPRESS_DB_NAME: wordpress
    volumes:
      - wordpress:/var/www/html

  db:
    image: mysql:8.0
    restart: always
    environment:
      MYSQL_DATABASE: wordpress
      MYSQL_USER: wordpress
      MYSQL_PASSWORD: wordpress
      MYSQL_RANDOM_ROOT_PASSWORD: '1'
    volumes:
      - db:/var/lib/mysql

volumes:
  wordpress:
  db:
```

Start the containers and complete the install wizard at `http://127.0.0.1:8080/`, leaving
the default *Hello World!* post in place:

```
docker compose up -d
```

Confirm the REST batch endpoint answers:

```
curl -s 'http://127.0.0.1:8080/?rest_route=/batch/v1' -X POST \
  -H 'Content-Type: application/json' --data '{"requests":[]}'
```

## Verification Steps

1. `msfconsole`
2. `use auxiliary/scanner/http/wordpress_wp2shell_sqli`
3. `set RHOSTS <target>`
4. `set RPORT <port>` (and `set SSL true` for HTTPS)
5. `run`
6. The module confirms the route-confusion primitive, confirms the time-based blind SQLi,
   and dumps `COUNT` rows of `user_login` and `user_pass` from the WordPress users table.

## Options

### COUNT

Number of users to enumerate from the users table (default: 3).

### TARGETURI

Base path to the WordPress application (default: `/`).

## Scenarios

### WordPress 7.0.1

```
msf6 > use auxiliary/scanner/http/wordpress_wp2shell_sqli
msf6 auxiliary(scanner/http/wordpress_wp2shell_sqli) > set RHOSTS 192.0.2.10
msf6 auxiliary(scanner/http/wordpress_wp2shell_sqli) > run

[+] 192.0.2.10:80 - REST batch route-confusion detected (CVE-2026-63030)
[+] 192.0.2.10:80 - Unauthenticated time-based blind SQL injection confirmed (CVE-2026-60137)
[+] {WPSQLi} Retrieved default table prefix: 'wp_'
    wp_users
    ========
    user_login  user_pass
    ----------  ---------
    admin       $P$B........................
[+] Loot saved to: /root/.msf4/loot/....._wordpress.users_......txt
[*] Scanned 1 of 1 hosts (100% complete)
```

## Notes

- For the full remote code execution chain, use
  `exploit/multi/http/wp_batch_desync_rce`. This auxiliary module is the read-only option
  for confirming the vulnerabilities and extracting WordPress user hashes.
- The module is read-only. It does not create posts, users, oEmbed cache entries, or other
  content; it only confirms the primitive and reads from the users table over the blind sink.
- Extraction is time-based blind, so a slow or heavily loaded target may need `SqliDelay`
  raised. `X-WP-Total` on the confused `get_items()` response is the boolean oracle.
- The `?rest_route=/batch/v1` form is used so the module works on installs without pretty
  permalinks, including where `/wp-json/` is headless-fronted or blocked.
