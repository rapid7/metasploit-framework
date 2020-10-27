## Vulnerable Application

This module detects vulnerable versions of FortiMail exploitable with an unauthenticated login bypass vulnerability.

Tested against the following versions of FortiMail:
- 5.4.9, 5.4.10, 5.4.11
- 6.0.5, 6.0.6, 6.0.7, 6.0.8, 6.0.9
- 6.2.1, 6.2.2, 6.2.3
- 6.4.0

## Verification Steps

- [ ] Start `msfconsole`
- [ ] `use auxiliary/scanner/http/fortimail_login_bypass_detection`
- [ ] `set RHOSTS <RHOSTS>`
- [ ] `set VERBOSE true`
- [ ] `run`
- [ ] **Verify** that systems are detected accordingly

## Scenarios

```
msf5 auxiliary(scanner/http/fortimail_login_bypass_detection) > run

[*] Checking vulnerability at 172.16.144.198
[+] 172.16.144.198 - Vulnerable version of FortiMail detected
[*] Scanned 1 of 4 hosts (25% complete)
[*] Checking vulnerability at 172.16.144.199
[+] 172.16.144.199 - Vulnerable version of FortiMail detected
[*] Scanned 2 of 4 hosts (50% complete)
[*] Checking vulnerability at 172.16.144.200
[+] 172.16.144.200 - Vulnerable version of FortiMail detected
[*] Scanned 3 of 4 hosts (75% complete)
[*] Checking vulnerability at 172.16.144.201
[-] 172.16.144.201 - Not vulnerable version of FortiMail detected
[*] Scanned 4 of 4 hosts (100% complete)
[*] Auxiliary module execution completed
```
