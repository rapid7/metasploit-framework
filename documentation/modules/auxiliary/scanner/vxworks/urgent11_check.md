## Vulnerable Application

  This detects systems running vulnerable versions of the Interpeak IPnet TCP/IP stack, which may be exploitable due to bugs parsing malformed network packets which can lead to memory corruption or denial-of-service attack possibilities.

## Verification Steps

  1. Do: `use auxiliary/scanner/vxworks/urgent11_check`
  2. Do: `set [RHOSTS]`, replacing `[RHOSTS]` with a list of hosts to test for the presence of the vulnerable IP stack.
  2. Do: `set [RPORTS]`, replacing `[RPORTS]` with a list of possible service ports to interrogate for vulnerable stack behavior.
  3. Do: ```run```
  4. If the host is exposing an identifiable IPnet TCP/IP stack, it will print the endpoint and report a vuln.

## Options

  **RPORTS** Set to a comma or space-delimited list of ports to check for the vulnerability.

  **VERBOSE** Set to see how the probabilities of a vulnerable host are calculated.

## Scenarios

```
msf5 auxiliary(scanner/vxworks/urgent11_check) > set RHOSTS 192.168.86.1 192.168.86.2
RHOSTS => 192.168.86.1 192.168.86.2
msf5 auxiliary(scanner/vxworks/urgent11_check) > set THREADS 2
THREADS => 2
msf5 auxiliary(scanner/vxworks/urgent11_check) > set RPORTS 21 22 23 80 443
RPORTS => 21 22 23 80 443
msf5 auxiliary(scanner/vxworks/urgent11_check) > run

[*] 192.168.86.1:21 being checked
[*] 192.168.86.2:21 being checked
[*] 192.168.86.1:22 being checked
[*] 192.168.86.1:23 being checked
[*] 192.168.86.1:80 being checked
[*] 192.168.86.1:443 being checked
[*] Scanned 1 of 2 hosts (50% complete)
[*] 192.168.86.2:22 being checked
[+] 192.168.86.2:22 affected by CVE-2019-12258
[*] 192.168.86.2:23 being checked
[*] 192.168.86.2:80 being checked
[*] 192.168.86.2:443 being checked
[+] 192.168.86.2:443 affected by CVE-2019-12258
[*] Scanned 2 of 2 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/vxworks/urgent11_check) >
```
