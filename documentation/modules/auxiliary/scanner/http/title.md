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

If set to `false`, will not store the captured information in notes. Use `notes -t http.title` to view. Defaults to `true`.

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

## Confirming using Burp Suite Community Edition

### HTTP GET Request 

```
GET / HTTP/1.1
Host: 172.17.0.2
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:69.0) Gecko/20100101 Firefox/69.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
```

### Server Response

```
HTTP/1.1 200 OK
Date: Wed, 16 Oct 2019 17:27:49 GMT
Server: Apache/2.4.38 (Debian)
X-Powered-By: PHP/7.2.23
Content-Length: 68
Connection: close
Content-Type: text/html; charset=UTF-8

<html><head><title>LOCAL TESTING</title></head><body></body></html>
```

## Confirming using Nikto

```
nikto -host http://172.17.0.2

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          172.17.0.2
+ Target Hostname:    172.17.0.2
+ Target Port:        80
+ Start Time:         2019-10-16 19:30:55 (GMT2)
---------------------------------------------------------------------------
+ Server: Apache/2.4.38 (Debian)
+ Retrieved x-powered-by header: PHP/7.2.23
```