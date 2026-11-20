## Vulnerable Application

[Splunk Enterprise](https://www.splunk.com/) 10.x ships a PostgreSQL "sidecar"
service that backs the Edge Processor, OpAmp, and SPL2 data-pipeline features. A
recovery endpoint exposed by that service through Splunk Web,

```
POST /<locale>/splunkd/__raw/v1/postgres/recovery/backup
```

performs **no authorization** ([CVE-2026-20253](https://advisory.splunk.com/advisories/SVD-2026-0603),
CVSS 9.8, CWE-306). An unauthenticated attacker can invoke arbitrary file
create/truncate operations, which researchers have chained to remote code
execution via PostgreSQL's `lo_export`.

Affected versions:

- **10.0.0 - 10.0.6** (fixed in **10.0.7**)
- **10.2.0 - 10.2.3** (fixed in **10.2.4**)
- 10.4.0 and later are not affected; Splunk Cloud Platform is not affected.

This module is **detection only** -- it mirrors the public watchTowr detection
artifact and never creates, truncates, or reads a file. It sends a POST to the
recovery endpoint with a non-Splunk (Basic) `Authorization` header:

- An affected build passes its (absent) authorization check and fails to decode
  the empty body -> **HTTP 400 `Failed to decode request`** -> reported vulnerable.
- A patched build rejects the Basic header -> **HTTP 401 `Authorization header
  must use Splunk token`** -> reported not vulnerable.
- Any other response -> the sidecar endpoint is not present (not vulnerable, or
  not Splunk Web).

The Basic header is required: an unauthenticated request returns HTTP 401 on both
affected and patched builds, so it does not discriminate.

### Setup with Docker

Splunk Enterprise 10.x bundles the PostgreSQL sidecar in the official image; no
extra configuration is needed to reproduce the endpoint.

Vulnerable:

```
docker run -d --name splunk-vuln -p 8000:8000 \
  -e SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com \
  -e SPLUNK_START_ARGS=--accept-license \
  -e SPLUNK_PASSWORD=Changeme123 \
  splunk/splunk:10.2.3
```

Patched (for the negative case): same command with `splunk/splunk:10.2.4`.

## Verification Steps

1. Start `msfconsole`.
2. `use auxiliary/scanner/http/splunk_postgres_sidecar_scanner`
3. `set RHOSTS <target>`
4. (If Splunk Web is HTTPS) `set SSL true` and adjust `RPORT`.
5. `run`
6. A vulnerable host prints a `[+]` and a reported vuln; a patched host prints a
   `[*] Not vulnerable` status.

## Options

### TARGETURI

The base path to Splunk Web. Default: `/`.

### LOCALE

The locale segment Splunk Web places in its URLs (e.g. `en-US`, `en-GB`). The
recovery endpoint is reached through `/<locale>/splunkd/__raw/...`. Default:
`en-US`.

## Scenarios

```
msf6 auxiliary(scanner/http/splunk_postgres_sidecar_scanner) > set RHOSTS 127.0.0.1
msf6 auxiliary(scanner/http/splunk_postgres_sidecar_scanner) > set RPORT 8000
msf6 auxiliary(scanner/http/splunk_postgres_sidecar_scanner) > run

[+] 127.0.0.1:8000 - Vulnerable: a non-Splunk Basic credential bypassed authorization on the PostgreSQL sidecar recovery endpoint (CVE-2026-20253)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Against a patched (10.2.4) instance:

```
[*] 127.0.0.1:8000 - Not vulnerable: the recovery endpoint requires a Splunk token (patched)
```
