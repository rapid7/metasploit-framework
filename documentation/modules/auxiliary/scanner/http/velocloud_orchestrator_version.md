## Vulnerable Application

This module fingerprints on-premises Arista (formerly VMware) VeloCloud
Orchestrator (VCO) web interfaces and reports whether the detected version falls
within a range affected by CVE-2026-93952, a critical improper input validation
flaw (CWE-20) in the Edge-to-VCO certificate authentication path.

The module is detection-only: it does not attempt to exploit the flaw. It first
confirms the target is a VeloCloud Orchestrator using the login favicon's
Shodan/nuclei-compatible MurmurHash3 (mmh3) hash, falling back to a landing-page
string match and finally a `/login/` `velocloud.*` `Set-Cookie` check. It then
makes a best-effort read of the product version and compares it against the
fixed releases published for each affected train. On current Arista-era hosted
builds the version is not exposed unauthenticated (see below), and the module
stops at product detection on those hosts.

### Affected versions

| Release train | Affected            | Fixed     |
| ------------- | ------------------- | --------- |
| 5.2           | `<= 5.2.3.15`       | `5.2.3.16`|
| 6.4           | `<= 6.4.2.7`        | `6.4.2.8` |
| 6.1           | `<= 6.1.3.7`        | pending   |
| 7.0           | `<= 7.0.0.2`        | pending   |

### Important caveats

* CVE-2026-93952 only affects orchestrators configured for certificate-based
  Edge-to-VCO authentication (Certificate Acquire or Certificate Required modes).
  This cannot be determined remotely by version fingerprinting, so a "Vulnerable"
  result means "running an affected version"; operators must confirm the Edge
  authentication mode to establish actual exposure.
* No public unauthenticated version endpoint is documented for VCO. On the
  Arista-era hosted builds tested during module development (see
  **Live-instance validation** below), no path exposed a build version string
  to unauthenticated callers, and on those hosts `get_version` returns `nil`
  and the module reports product detection only. On older or on-premises
  builds that do leak a version string via the SPA landing page, the module
  still emits the full affected/not-affected verdict.

### Setup

There is no public test image for VeloCloud Orchestrator. Run this module
against a VCO On-Prem instance you are authorized to assess.

### Live-instance validation

The favicon hash and detection surface were validated on 2026-11-08 against
two Arista-hosted Orchestrators (`vco1-usvi1.velocloud.net` and
`vco996-usvi1.velocloud.net`) by passive GET-only probing. Findings:

* `GET /apps/root/favicon.ico` returns a 1406-byte ICO whose
  `mmh3(base64.encodebytes(body))` is `-2062596654` on both hosts, under both
  this module's Ruby `mmh3_x86_32` and the reference Python `mmh3` library.
  This is the path the module now queries first; `/favicon.ico` is kept as a
  fallback for older builds, where the Angular SPA router intercepts that
  path and returns the landing HTML.
* `GET /` returns a 750-byte Angular SPA shell referencing
  `@velocloud/vco-header`, which the module's `looks_like_vco?` fallback
  matches via the lowercase `velocloud` substring.
* `GET /login/` returns a 302 that sets `velocloud.session`, `velocloud.csrf`
  and `velocloud.message` cookies, used by `login_cookie_match?` as a
  last-resort product signal.
* `GET /portal/`, `GET /portal/rest/` and
  `GET /portal/rest/login/enterpriseLogin` all return 404. The Angular SPA
  entry at `/apps/root/main.js` only loads
  `/apps/root/assets/module-federation.manifest.json`, which is empty (`{}`)
  until the user authenticates, so the microfrontends that would carry
  version metadata are not reachable unauthenticated. No `Server` or
  `X-*-Version` response headers are emitted. On these builds the module's
  version-read patterns do not match and the vulnerable-range comparison is
  skipped.

## Verification Steps

1. Start `msfconsole`.
2. `use auxiliary/scanner/http/velocloud_orchestrator_version`
3. `set RHOSTS <target>`
4. (Optional) adjust `RPORT`, `SSL`, or `TARGETURI` for the deployment.
5. `run`
6. The module reports whether VCO was detected, the version if it could be read,
   and whether that version is within a range affected by CVE-2026-93952.

## Options

### TARGETURI

The base path to the VeloCloud Orchestrator web interface. Defaults to `/`.

## Scenarios

### Affected version detected

```
msf6 > use auxiliary/scanner/http/velocloud_orchestrator_version
msf6 auxiliary(scanner/http/velocloud_orchestrator_version) > set RHOSTS vco.example.com
RHOSTS => vco.example.com
msf6 auxiliary(scanner/http/velocloud_orchestrator_version) > run

[+] vco.example.com:443 - VeloCloud Orchestrator version 6.4.2.7 detected
[!] vco.example.com:443 - Version 6.4.2.7 is within a range affected by CVE-2026-93952 (confirm certificate-based Edge authentication is enabled to establish exposure)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Product detected, version not readable

```
msf6 auxiliary(scanner/http/velocloud_orchestrator_version) > run

[*] vco.example.com:443 - VeloCloud Orchestrator detected, but version could not be determined
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
