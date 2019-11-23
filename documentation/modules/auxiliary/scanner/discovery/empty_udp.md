## Vulnerable Application
Detect UDP services that reply to empty probes.

More information can be found on the [Rapid7 blog page](https://blog.rapid7.com/2014/10/03/adventures-in-empty-udp-scanning/)

## Verification Steps

1. Start msfconsole
2. Do: `use auxiliary/scanner/discovery/empty_udp`
3. Do: `set RHOSTS [ip]`
4. Do: `set RPORT [port]`
4. Do: `run`

## Scenarios

### A run against Windows XP (X64) using Kali Linux 2019.3

  ```
  msf auxiliary(scanner/dns/dns_amp) > use auxiliary/scanner/discovery/empty_udp
  msf auxiliary(scanner/discovery/empty_udp) > set RHOSTS 1.1.1.1
    RHOSTS => 1.1.1.1
  msf auxiliary(scanner/discovery/empty_udp) > set RPORT 135
    RPORT => 135
  msf auxiliary(scanner/discovery/empty_udp) > run
    [*] Sending 1032 empty probes to 1.1.1.1->1.1.1.1 (1 hosts)
    [+] Received #52 from #:135:#1095/udp
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed
  ```
