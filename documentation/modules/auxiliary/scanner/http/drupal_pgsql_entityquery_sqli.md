## Vulnerable Application

CVE-2026-9082 (Drupal SA-CORE-2026-004) affects Drupal core versions >= 8.9.0
< 10.4.10, >= 10.5.0 < 10.5.10, >= 10.6.0 < 10.6.9, >= 11.0.0 < 11.1.10,
>= 11.2.0 < 11.2.12, and >= 11.3.0 < 11.3.10 on PostgreSQL. Drupal 8.9 and 9
require the advisory's manual patches because those branches are EOL.
MySQL, MariaDB, and SQLite are not affected.

### Setup with Podman

From the Metasploit Framework checkout, create vulnerable Drupal 11.2.0 and
patched Drupal 11.2.12 targets:

```bash
set -euo pipefail

wait_for() {
  description="$1"
  shift
  for attempt in $(seq 1 90); do
    if "$@"; then
      return 0
    fi
    sleep 2
  done
  echo "Timed out waiting for $description" >&2
  return 1
}

podman network create drupal-net
podman run -d --name drupal-pg --network drupal-net \
  -e POSTGRES_DB=drupal -e POSTGRES_USER=drupal -e POSTGRES_PASSWORD=drupal \
  docker.io/library/postgres:16.3-alpine
wait_for PostgreSQL podman exec drupal-pg pg_isready -U drupal
podman exec drupal-pg createdb -U drupal drupal_patched

install_drupal() {
  name="$1"; image="$2"; port="$3"; db_url="$4"
  podman run -d --name "$name" --network drupal-net -p "127.0.0.1:$port:80" \
    "docker.io/library/drupal:$image-apache"
  podman exec "$name" sh -c \
    'cd /opt/drupal && composer require drush/drush:13.7.0 --no-interaction'
  podman exec "$name" sh -c \
    "cd /opt/drupal && vendor/bin/drush site:install standard --db-url=$db_url --account-pass=adminpass -y"
  podman exec "$name" sh -c \
    'cd /opt/drupal && vendor/bin/drush pm:enable jsonapi -y'
  podman exec "$name" sh -c \
    'cd /opt/drupal && vendor/bin/drush php:eval '\''\Drupal\node\Entity\Node::create(["type"=>"article","title"=>"Test"])->save();'\'''
}

install_drupal drupal-web-pg 11.2.0 8080 pgsql://drupal:drupal@drupal-pg/drupal
install_drupal drupal-web-patched 11.2.12 8082 pgsql://drupal:drupal@drupal-pg/drupal_patched

for port in 8080 8082; do
  wait_for "Drupal JSON:API on port $port" curl -fsS \
    "http://127.0.0.1:$port/jsonapi/node/article"
done
```

Mount the unmerged module and join the target network:

```bash
podman run -it --rm --name msf --network drupal-net \
  -v "$PWD/modules/auxiliary/scanner/http/drupal_pgsql_entityquery_sqli.rb:/usr/src/metasploit-framework/modules/auxiliary/scanner/http/drupal_pgsql_entityquery_sqli.rb:ro,Z" \
  docker.io/metasploitframework/metasploit-framework:latest ./msfconsole
```

With Docker, replace `podman` with `docker` and remove `,Z` from the bind mount.

## Verification Steps

1. Create the targets and start msfconsole as shown above.
1. Run `use auxiliary/scanner/http/drupal_pgsql_entityquery_sqli`.
1. Set `RHOSTS` to `drupal-web-pg` and `RPORT` to `80`.
1. Run the module and confirm Drupal 11.2.0 is reported vulnerable.
1. Repeat with `RHOSTS` set to `drupal-web-patched` and confirm it is safe.

## Options

### JSONAPI_RESOURCE

An anonymously readable JSON:API resource as `entity_type/bundle`. It must expose
at least one entity. (Default: `node/article`)

### JSONAPI_FIELD

A case-insensitive string field on `JSONAPI_RESOURCE`. (Default: `title`)

### SqliDelay

The delay used for the time-based check. Increase it on high-latency targets.
(Default: `3.0`)

## Scenarios

### Drupal 11.2.0 and 11.2.12 on PostgreSQL 16.3

```
msf > use auxiliary/scanner/http/drupal_pgsql_entityquery_sqli
msf auxiliary(scanner/http/drupal_pgsql_entityquery_sqli) > set RPORT 80
RPORT => 80
msf auxiliary(scanner/http/drupal_pgsql_entityquery_sqli) > set RHOSTS drupal-web-pg
RHOSTS => drupal-web-pg
msf auxiliary(scanner/http/drupal_pgsql_entityquery_sqli) > run
[+] 10.89.8.7:80          - The target is vulnerable. Time-based blind SQL injection via JSON:API filter array key
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/http/drupal_pgsql_entityquery_sqli) > set RHOSTS drupal-web-patched
RHOSTS => drupal-web-patched
msf auxiliary(scanner/http/drupal_pgsql_entityquery_sqli) > run
[*] 10.89.8.8:80          - The target is not exploitable. No time-based SQL injection response detected
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Cleanup

```bash
podman rm -f drupal-web-pg drupal-web-patched drupal-pg 2>/dev/null || true
podman network rm drupal-net 2>/dev/null || true
```
