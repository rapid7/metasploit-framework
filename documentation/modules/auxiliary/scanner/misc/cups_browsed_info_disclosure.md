## Vulnerable Application

Retrieve CUPS version and kernel version information from `cups-browsed` services.


## Verification Steps

1. Do: `use modules/auxiliary/scanner/misc/cups_browsed_info_disclosure`
2. Do: `set rhosts [ips]`
3. Do: `run`

## Options


## Scenarios

### Scanning a local network for CUPS services

```
msf6 > use modules/auxiliary/scanner/misc/cups_browsed_info_disclosure
msf6 auxiliary(scanner/misc/cups_browsed_info_disclosure) > set rhosts 192.168.200.0/24
rhosts => 192.168.200.0/24
msf6 auxiliary(scanner/misc/cups_browsed_info_disclosure) > run
[*] Auxiliary module running as background job 0.
msf6 auxiliary(scanner/misc/cups_browsed_info_disclosure) > 
[*] Using URL: http://192.168.200.130:8080/printers/s65WzxwTmx
[+] 192.168.200.132: CUPS/2.3.1 (Linux 5.4.0-187-generic; x86_64) IPP/2.0
[+] 192.168.200.139: CUPS/2.4.7 (Linux 6.8.0-31-generic; x86_64) IPP/2.0
[*] Scanned 256 of 256 hosts (100% complete)
[*] Server stopped.
```
