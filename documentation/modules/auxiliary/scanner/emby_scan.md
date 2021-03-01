## Vulnerable Application
This module has been tested on Emby Media Server versions older than 4.5.

## Description

Generates a GET request to the provided web servers and executes an SSRF against the targeted EMBY server. Returns the server header, HTML title attribute and location header (if set). This is useful for rapidly identifying  web applications on the internal network using the Emby SSRF vulnerability (CVE-2020-26948).

## Verification Steps

  1. Do: `use auxiliary/scanner/emby_scan`
  2. Do: `set rhosts [ips]`
  3. Do: `set emby_server [emby_server_ip]`
  4. Do: `run`

## Options


**PORTS**

Select which ports to check for HTTP servers internal to the Emby server. Defaults to 80, 8080, 8081, 8888.


**EMBY_SERVER**

IP address of the Emby server to use. Required.


**EMBY_PORT**

Emby server access port. Defaults to 8096.

**SHOW_TITLES**

If set to `false`, will not show the titles on the console as they are grabbed. Defaults to `true`.

**STORE_NOTES**

If set to `false`, will not store the captured information in notes. Use `notes -t http.title` to view. Defaults to `true`.

## Scenarios

### Emby Scan Internal 192.168.1.0 Network

  ```
msf6 > use auxiliary/scanner/emby_scan
msf6 auxiliary(scanner/http/title) > set RHOSTS 192.168.1.0/24
RHOSTS => 192.168.1.0/24
msf6 auxiliary(scanner/http/title) > set EMBY_SERVER 10.10.10.1
RHOSTS => 192.168.1.0/24

msf6 auxiliary(scanner/emby_scan) > run

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
  ```
