This module provides a port of Daniel Mende's (released under the BSD license) gtp-scan.py utility. It brings the ability to scan for GPRS servers to Metasploit via sending GTP-U v1 and v2 echo requests.

## Vulnerable Application

Open-source GGSN implementations can be used as a target for this module as well as commercial GPRS gear. FOr information on one project suitable as a target, see OsmoGGSN: https://osmocom.org/projects/openggsn/wiki/OsmoGGSN

## Options

   **The RPORT option**

   This option can be changed to target GTP-U (2152) or GTP-C (2123), which both use the same packet type for echo probing.

## Scenarios

```
metasploit-framework (S:0 J:1) auxiliary(scanner/gprs/gtp_echo) > set RHOSTS 192.168.28.200-192.168.28.208
RHOSTS => 192.168.28.200-192.168.28.208
metasploit-framework (S:0 J:1) auxiliary(scanner/gprs/gtp_echo) > run

[*] [2019.04.22-16:38:27] Sending probes to 192.168.28.200->192.168.28.208 (9 hosts)
[+] [2019.04.22-16:38:42] GTP v1 echo response received from: 192.168.28.200:2152
[+] [2019.04.22-16:38:43] GTP v1 echo response received from: 192.168.28.201:2152
[+] [2019.04.22-16:38:43] GTP v1 echo response received from: 192.168.28.207:2152
[+] [2019.04.22-16:38:43] GTP v1 echo response received from: 192.168.28.208:2152
[*] [2019.04.22-16:38:43] Scanned 9 of 9 hosts (100% complete)
[*] Auxiliary module execution completed
metasploit-framework (S:0 J:1) auxiliary(scanner/gprs/gtp_echo) >
```
