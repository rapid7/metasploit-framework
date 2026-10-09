## Vulnerable Application

This module checks an on-premises Arista (formerly VMware) VeloCloud Orchestrator
(VCO) host for the published host-side indicators of compromise (IOCs) associated
with exploitation of CVE-2026-93952, a critical improper input validation flaw
(CWE-20).

It is a defensive, read-only forensic check intended to be run through an existing
session on a VCO host the operator administers. It does not exploit anything. On
each run it:

* looks for known malicious file artifacts on disk,
* computes the MD5 of a known implant binary and compares it to the published
  hash,
* looks for the malicious `systemd` service unit in the usual locations, and
* scans available nginx access logs for the reported attacker IP addresses.

A match indicates the host should be treated as compromised and taken through the
vendor's incident response guidance. The absence of matches is **not** proof the
host is clean; attacker artifacts may differ from the published set.

### Indicators checked

| Category      | Indicator |
| ------------- | --------- |
| File          | `/usr/local/sbin/.vcnode.js`, `/usr/local/sbin/vc-sysmond` |
| Hash          | `vc-sysmond` MD5 `dc78e206eaeadec59fc5801fe4556bd0` |
| systemd unit  | `vc-sysmon.service` (under `/etc/`, `/lib/`, `/usr/lib/` systemd paths) |
| Attacker IPs  | `142.93.149.77`, `104.248.126.159` (in nginx access logs) |

### Setup

There is no public test image for VeloCloud Orchestrator. Obtain a shell or
Meterpreter session on a VCO On-Prem host you are authorized to inspect, then run
this module against that session.

## Verification Steps

1. Obtain a `shell` or `meterpreter` session on the target VCO host.
2. `use post/linux/gather/velocloud_cve_2026_93952_ioc_check`
3. `set SESSION <session id>`
4. `run`
5. Review the reported indicators. Any match is recorded as a vulnerability and a
   note against the session host.

## Options

### SESSION

The session to run the module on. This is the only required option.

## Scenarios

### Compromised host

```
msf6 post(linux/gather/velocloud_cve_2026_93952_ioc_check) > run

[*] Checking host for CVE-2026-93952 indicators of compromise
[-] Malicious artifact present: /usr/local/sbin/vc-sysmond
[-] /usr/local/sbin/vc-sysmond matches known implant MD5 dc78e206eaeadec59fc5801fe4556bd0
[-] Malicious systemd unit present: /etc/systemd/system/vc-sysmon.service
[-] Attacker IP 142.93.149.77 found in /var/log/nginx/access.log
[!] 4 indicator(s) of compromise found - treat this host as compromised
[*] Post module execution completed
```

### No indicators found

```
msf6 post(linux/gather/velocloud_cve_2026_93952_ioc_check) > run

[*] Checking host for CVE-2026-93952 indicators of compromise
[*] No published CVE-2026-93952 indicators of compromise were found
[*] Note: a clean result is not proof the host is uncompromised
[*] Post module execution completed
```
