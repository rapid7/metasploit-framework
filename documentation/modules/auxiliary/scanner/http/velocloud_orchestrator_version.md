## Vulnerable Application

This module fingerprints on-premises Arista (formerly VMware) VeloCloud
Orchestrator (VCO) web interfaces and reports whether the detected version falls
within a range affected by CVE-2026-93952, a CVSS 10.0 improper input validation
flaw (CWE-20) in the Edge-to-VCO certificate authentication path.

The module is detection-only: it does not attempt to exploit the flaw. It first
confirms the target is a VeloCloud Orchestrator using the login favicon's
Shodan/nuclei-compatible MurmurHash3 (mmh3) hash, falling back to a string match
in the landing page when no favicon is served. It then makes a best-effort read
of the product version and compares it against the fixed releases published for
each affected train.

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
* No public unauthenticated version endpoint is documented for VCO. The favicon
  hash reliably identifies the product but not its version, and the version-read
  path is a best effort that should be validated against a live instance before
  the result is treated as authoritative.

### Setup

There is no public test image for VeloCloud Orchestrator. Run this module
against a VCO On-Prem instance you are authorized to assess.

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
