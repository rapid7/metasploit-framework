## Vulnerable Application

[Audiobookshelf](https://www.audiobookshelf.org/) is a self-hosted audiobook and
podcast server. Versions **2.17.0 through 2.19.0** are affected by
[CVE-2025-25205](https://github.com/advplyr/audiobookshelf/security/advisories/GHSA-pg8v-5jcv-wrvw),
an unauthenticated authentication bypass.

The authentication middleware (`server/Auth.js`) decides whether a `GET` request
may skip authentication by testing unanchored regular expressions
(`/\/api\/items\/[^/]+\/cover/` and `/\/api\/authors\/[^/]+\/image/`) against
`req.originalUrl`, which includes the query string, instead of the normalized
`req.path`. An unauthenticated request to a protected API endpoint that appends a
query value containing one of those substrings — for example
`/api/libraries?r=/api/items/1/cover` — satisfies the "auth not needed" check
while Express still routes it to the protected handler. Depending on the endpoint
this leaks protected data, or returns an HTTP 500 where the handler dereferences
the now-undefined user object. The issue was fixed in **2.19.1** by anchoring the
patterns and matching `req.path`.

This module fingerprints the server and version through the unauthenticated
`/status` endpoint, then performs a differential check against the protected
`/api/libraries` endpoint: a baseline request that a server normally rejects with
HTTP 401, and a bypass request carrying the whitelisted substring. On a vulnerable
server the auth check is skipped and the bypass request is processed (HTTP 200, or
500 because the handler runs without a user); a patched server returns 401 to
both. The 500 is request-level and the server stays up. The module deliberately
avoids endpoints such as `/api/users` that crash the server process (the
denial-of-service half of this CVE).

### Setup with Docker

A vulnerable instance can be run with the official image pinned to a vulnerable
tag:

```
docker run -d --name abs-vuln -p 13378:80 ghcr.io/advplyr/audiobookshelf:2.19.0
```

Browse to `http://127.0.0.1:13378` and complete the initial root-user setup. This
is required: before initialization the server returns HTTP 500 to the protected
API. After setup, the bypass request to `/api/libraries` returns HTTP 500 on a
vulnerable server (the auth check is skipped and the handler runs without a user),
which the module treats as confirmation; the same request returns HTTP 401 on a
patched server.

To confirm the true-negative behavior, run a patched instance on a different port
and complete its setup the same way:

```
docker run -d --name abs-patched -p 13379:80 ghcr.io/advplyr/audiobookshelf:2.19.1
```

## Verification Steps

1. Start a vulnerable Audiobookshelf instance and complete its setup (see Setup with Docker)
1. Start `msfconsole`
1. Do: `use auxiliary/scanner/http/audiobookshelf_auth_bypass`
1. Do: `set RHOSTS <target>`
1. Do: `set RPORT 13378`
1. Do: `run`
1. The module reports the detected version and confirms the authentication bypass

## Options

### TARGETURI

The base path to the Audiobookshelf application. Defaults to `/`. Set this when
Audiobookshelf is served from a sub-path behind a reverse proxy.

## Scenarios

### Audiobookshelf 2.19.0 (vulnerable)

```
msf6 > use auxiliary/scanner/http/audiobookshelf_auth_bypass
msf6 auxiliary(scanner/http/audiobookshelf_auth_bypass) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 auxiliary(scanner/http/audiobookshelf_auth_bypass) > set RPORT 13378
RPORT => 13378
msf6 auxiliary(scanner/http/audiobookshelf_auth_bypass) > run

[+] 127.0.0.1:13378       - Audiobookshelf 2.19.0 - unauthenticated API authentication bypass confirmed (CVE-2025-25205)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Audiobookshelf 2.19.1 (patched, true-negative)

```
msf6 auxiliary(scanner/http/audiobookshelf_auth_bypass) > set RPORT 13379
RPORT => 13379
msf6 auxiliary(scanner/http/audiobookshelf_auth_bypass) > run

[*] 127.0.0.1:13379       - Audiobookshelf 2.19.1 - not vulnerable (authentication enforced)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
