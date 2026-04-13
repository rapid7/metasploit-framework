## Vulnerable Application

Inductive Automation Ignition is a widely deployed SCADA platform used in critical
infrastructure worldwide. This module targets an unauthenticated information disclosure
present across all major Ignition versions — the gateway exposes version, run state,
OS, Java runtime, and GAN redundancy topology without any credentials.

Ignition can be downloaded from [inductiveautomation.com](https://inductiveautomation.com/downloads/ignition).
A free 2-hour trial license is available and resets on restart, which is sufficient
for testing purposes.

The endpoint and response format differ by version:

| Version | Endpoint | Format |
|---|---|---|
| 7.9.x | `/main/system/gwinfo` | semicolon-delimited key=value |
| 8.0.x | `/system/gwinfo` | semicolon-delimited key=value |
| 8.1.x | `/system/StatusPing` | JSON |
| 8.3.x | `/system/gwinfo` | semicolon-delimited key=value |

This module has been tested against the following Ignition versions on Linux:

* 7.9.21
* 8.1.15
* 8.1.17
* 8.3.4

8.0.x behavior is inferred from the source of the existing
`exploit/multi/scada/inductive_ignition_rce` module, which uses `/system/gwinfo`
for version detection prior to exploitation.

## Verification Steps

1. Install Ignition (any version 7.9+) and complete initial gateway commissioning
2. Start msfconsole
3. `use auxiliary/scanner/scada/ignition_statusping`
4. `set RHOSTS <target IP>`
5. `run`
6. The module should return gateway version, state, OS, Java runtime, and GAN role

## Options

### RHOSTS

The target host(s) or CIDR range to scan. Supports standard MSF RHOSTS syntax
including comma-separated IPs and CIDR notation (e.g. `10.10.0.0/24`).

### RPORT

The Ignition gateway HTTP port. Default: `8088`. Ignition can be configured to run
on alternate ports — common alternatives include `80`, `443`, `8043`.

## Scenarios

### Ignition 7.9.21 — Single host

```
msf6 > use auxiliary/scanner/scada/ignition_statusping
msf6 auxiliary(scanner/scada/ignition_statusping) > set RHOSTS 159.203.120.32
RHOSTS => 159.203.120.32
msf6 auxiliary(scanner/scada/ignition_statusping) > run

[+] 159.203.120.32:8088 - Ignition 7.9.21 | State: RUNNING | OS: Linux | GAN role: Independent
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Mixed version network scan — CIDR range

The following shows a scan across a /24 containing gateways at multiple versions,
including an 8.3.4 GAN redundancy pair (Master + Backup):

```
msf6 > use auxiliary/scanner/scada/ignition_statusping
msf6 auxiliary(scanner/scada/ignition_statusping) > set RHOSTS 10.10.0.0/24
RHOSTS => 10.10.0.0/24
msf6 auxiliary(scanner/scada/ignition_statusping) > run

[+] 10.10.0.3:8088 - Ignition 8.3.4 | State: RUNNING | OS: Linux | Java: 17.0.17 | GAN role: Master
[+] 10.10.0.4:8088 - Ignition 8.3.4 | State: RUNNING | OS: Linux | Java: 17.0.17 | GAN role: Backup
[+] 10.10.0.7:8088 - Ignition 7.9.21 | State: RUNNING | OS: Linux | GAN role: Independent
[+] 10.10.0.8:8088 - Ignition 8.1.15 | State: RUNNING | OS: Linux | Java: 11.0.14.1 | GAN role: Independent
[*] Scanned 256 of 256 hosts (100% complete)
[*] Auxiliary module execution completed
```

The GAN role output (Master/Backup) identifies redundancy pairs and reveals the network
topology of the Ignition deployment without authentication. This complements
`exploit/multi/scada/inductive_ignition_rce` (CVE-2020-10644), which targets 8.0.x only,
by extending fingerprinting coverage to 7.9.x, 8.1.x, and 8.3.x.
