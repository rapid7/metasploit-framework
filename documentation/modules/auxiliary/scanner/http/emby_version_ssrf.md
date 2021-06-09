## Vulnerable Application
This scanner should work on any version of Emby Media Server. Data returned would depend on configuration
settings server-side.

### Description

Generates an API request to the provided IP addresses in order to ascertain the Emby server version, if possible.
Returns the server version, URI, and internal IP address (if provided). This is useful for rapidly identifying vulnerable
Emby servers that may be susceptible to CVE-2020-26948.

## Verification Steps

  1. Do: `use auxiliary/scanner/http/emby_version_ssrf`
  2. Do: `set rhosts [ips]`
  3. Do: `run`

## Options

## Scenarios
### Emby Server 4.4.3.0 
```
msf6 > use auxiliary/scanner/http/emby_version_ssrf
msf6 auxiliary(scanner/http/emby_version_ssrf) > set rhosts 10.10.200.32
rhosts => 10.10.200.32
msf6 auxiliary(scanner/http/emby_version_ssrf) > run

[*] Identifying Media Server Version on 10.10.200.32:8096
[+] [Media Server] URI: http://10.10.200.32:8096  /
[+] [Media Server] Version: 4.4.2.0
[+] [Media Server] Internal IP: http://192.168.2.3:8096
[+] *** Vulnerable to SSRF module auxiliary/scanner/emby_ssrf_scanner! ***
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
