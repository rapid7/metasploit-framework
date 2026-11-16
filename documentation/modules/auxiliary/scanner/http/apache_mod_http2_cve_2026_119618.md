## Vulnerable Application

CVE-2026-119618 is a race condition in Apache HTTP Server's `mod_http2`. It affects Apache
httpd **2.4.55 through 2.4.70** when HTTP/2 is enabled, and is fixed in **2.4.71** (Red Hat
CVSS 9.8). This module is detection-only: it reads the `Server` banner, checks whether the
reported version is in the affected range, and reports whether HTTP/2 is advertised. It sends
a single benign `GET /` and does not attempt to trigger the race.

A reproducible lab can be built from the official `httpd` Docker images with `mod_http2` and
cleartext HTTP/2 (`h2c`) enabled.

Vulnerable target (2.4.70). `Dockerfile`:

```
FROM httpd:2.4.70
RUN sed -i 's|^#LoadModule http2_module|LoadModule http2_module|' /usr/local/apache2/conf/httpd.conf \
 && printf '\nProtocols h2 h2c http/1.1\nProtocolsHonorOrder On\nH2Upgrade on\nServerName localhost\n' >> /usr/local/apache2/conf/httpd.conf
```

```
docker build -t http2lab-vuln:2.4.70 .
docker run -d --name http2lab-vuln -p 8070:80 http2lab-vuln:2.4.70
```

Patched negative-control target: repeat with `FROM httpd:2.4.71` and publish it on port 8071.

Note: this is version-based detection. Linux distributions backport the fix without changing
the version string, so a banner match on a distribution build (for example
`Apache/2.4.58 (Debian)`) is a lead to verify rather than proof of exposure. mod_http2 can
also be enabled without advertising h2 on a plaintext HTTP/1.1 response; for TLS targets,
confirm HTTP/2 via ALPN.

## Verification Steps

1. Build and start the lab targets above (vulnerable 2.4.70 on 8070, patched 2.4.71 on 8071).
1. Start `msfconsole`.
1. Do: `use auxiliary/scanner/http/apache_mod_http2_cve_2026_119618`
1. Do: `set RHOSTS 127.0.0.1`
1. Do: `set RPORT 8070`
1. Do: `set VERBOSE true`
1. Do: `run`
1. You should get a `[+]` finding that the version is in the affected range, and a reported vulnerability.
1. Do: `set RPORT 8071` then `run` again. The patched host is reported as outside the affected range and no vulnerability is recorded.

## Options

### RPORT

The target HTTP(S) port. (Default: `80`)

### SSL

Set to `true` for HTTPS targets. The reported service name follows this setting (`http` or `https`).

### VERBOSE

When `true`, the module also logs hosts that are out of the affected range or that do not expose an Apache version. (Default: `false`)

## Scenarios

### Apache httpd 2.4.70 with HTTP/2 (vulnerable) and 2.4.71 (patched), via the Docker lab above

```
msf6 > use auxiliary/scanner/http/apache_mod_http2_cve_2026_119618
msf6 auxiliary(scanner/http/apache_mod_http2_cve_2026_119618) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 auxiliary(scanner/http/apache_mod_http2_cve_2026_119618) > set RPORT 8070
RPORT => 8070
msf6 auxiliary(scanner/http/apache_mod_http2_cve_2026_119618) > set VERBOSE true
VERBOSE => true
msf6 auxiliary(scanner/http/apache_mod_http2_cve_2026_119618) > run

[+] Apache/2.4.70 in CVE-2026-119618 range (2.4.55-2.4.70); HTTP/2 advertised. NOTE: distro backports may patch without changing the version string - verify.
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

msf6 auxiliary(scanner/http/apache_mod_http2_cve_2026_119618) > set RPORT 8071
RPORT => 8071
msf6 auxiliary(scanner/http/apache_mod_http2_cve_2026_119618) > run

[*] Apache/2.4.71 is outside the affected range (2.4.55-2.4.70)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

On an upstream build the framework prepends `host:port` to each line (for example
`[+] 127.0.0.1:8070 - Apache/2.4.70 ...`).
