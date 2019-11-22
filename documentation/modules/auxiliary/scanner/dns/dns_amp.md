## Vulnerable Application

This module can be used to discover DNS servers which expose recursive name lookups which can be used in an amplification attack against a third party.

BIND 9.4.1-P1 source: ftp://ftp.isc.org/isc/bind9/9.4.1-P1/bind-9.4.1-P1.tar.gz
Ubuntu 7.10 (Gutsy Gibbon): http://old-releases.ubuntu.com/releases/7.10/


## Verification Steps

  1. Start msfconsole
  2. Do: `use modules/auxiliary/scanner/dns/dns_amp`
  3. Do: `set DOMAINNAME [domain]`
  4. Do: `set RHOST [ip]`
  4. Do: `run`

## Scenarios

### A run on Ubuntu 7.10 (Gutsy Gibbon) and BIND 9.4.1-P1

  ```
  msf > use modules/auxiliary/scanner/dns/dns_amp
  msf auxiliary(scanner/dns/dns_amp) > set DOMAINNAME domain.com
    DOMAINNAME => domain.com
  msf auxiliary(scanner/dns/dns_amp) > set RHOSTS 192.168.10.254
    RHOSTS => 192.168.10.254
  msf auxiliary(scanner/dns/dns_amp) > run
    [*] Sending DNS probes to 192.168.10.254->192.168.10.254 (1 hosts)
    [*] Sending 70 bytes to each host using the IN ANY domain.com request
    [+] 192.168.10.254:53 - Response is 374 bytes [5.34x Amplification]
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed
  ```
