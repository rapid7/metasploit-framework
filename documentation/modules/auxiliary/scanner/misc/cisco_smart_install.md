## Vulnerable Application

  Any system exposing the Cisco Smart Install (SMI) protocol, which typically runs on TCP port 4786.

## Verification Steps

  1. Do: ```use auxiliary/scanner/misc/cisco_smart_install```
  2. Do: ```set [RHOSTS]```, replacing ```[RHOSTS]``` with a list of hosts to test for the presence of SMI
  3. Do: ```run```
  4. If the host is exposing an identifiable SMI instance, it will print the endpoint.


## Scenarios

  ```
msf auxiliary(cisco_smart_install) > run

[*] Scanned  57 of 512 hosts (11% complete)
[*] Scanned 105 of 512 hosts (20% complete)
[*] Scanned 157 of 512 hosts (30% complete)
[*] Scanned 212 of 512 hosts (41% complete)
[*] Scanned 256 of 512 hosts (50% complete)
[*] Scanned 310 of 512 hosts (60% complete)
[*] Scanned 368 of 512 hosts (71% complete)
[*] Scanned 413 of 512 hosts (80% complete)
[*] Scanned 466 of 512 hosts (91% complete)
[+] a.b.c.d:4786   - Fingerprinted the Cisco Smart Install protocol
[*] Scanned 512 of 512 hosts (100% complete)
[*] Auxiliary module execution completed
```
