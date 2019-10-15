## Description

Generates a GET request to the provided web servers and returns the server header, HTML title attribute and location header (if set). This is useful for rapidly identifying interesting web applications en mass.

## Verification Steps

  1. Do: `use auxiliary/scanner/http/title`
  2. Do: `set rhosts [ips]`
  3. Do: `run`

## Options

**SHOW_TITLES**

If set to `false`, will not show the titles on the console as they are grabbed. Defaults to `true`.

**STORE_NOTES**

If set to `false`, will not store the captured information in notes. Use "notes -t http.title" to view. Defaults to `true`.

## Scenarios

### Apache/2.4.38 inside a Docker container

  ```
msf5 > use auxiliary/scanner/http/title
msf5 auxiliary(scanner/http/title) > set RHOSTS 172.17.0.2
RHOSTS => 172.17.0.2
msf5 auxiliary(scanner/http/title) > run

[+] [172.17.0.2:80] [C:200] [R:] [S:Apache/2.4.38 (Debian)] LOCAL TESTING
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
  ```
