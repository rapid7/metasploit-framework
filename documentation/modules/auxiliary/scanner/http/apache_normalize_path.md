This module scan for an unauthenticated RCE vulnerability which exists in Apache version 2.4.49 (CVE-2021-41773).

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
2. `use auxiliary/scanner/http/apache_normalize_path`
3. `set RHOSTS [IP]`
4. `run`

## Options

**DEPTH**

Depth for path traversal. Default: 5

**TARGETURI**

Base path. Default: `/cgi-bin`

## Scenarios

```
msf6 auxiliary(scanner/http/apache_normalize_path) > options 

Module options (auxiliary/scanner/http/apache_normalize_path):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   DEPTH      5                yes       Depth for Path Traversal
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     172.20.4.12      yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      8080             yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /cgi-bin         yes       Base path
   THREADS    1                yes       The number of concurrent threads (max one per host)
   VHOST                       no        HTTP server virtual host

msf6 auxiliary(scanner/http/apache_normalize_path) > set RHOSTS 172.20.4.12
RHOSTS => 172.20.4.12
msf6 auxiliary(scanner/http/apache_normalize_path) > set RPORT 8080
RPORT => 8080
msf6 auxiliary(scanner/http/apache_normalize_path) > set SSL false 
SSL => false
msf6 auxiliary(scanner/http/apache_normalize_path) > run

[+] http://172.20.4.12:8080 - The target is vulnerable to CVE-2021-41773.
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/apache_normalize_path) > vulns 

Vulnerabilities
===============

Timestamp                Host         Name                                 References
---------                ----         ----                                 ----------
2021-10-06 19:05:27 UTC  172.20.4.12  Apache 2.4.49 Traversal RCE scanner  CVE-2021-41773,URL-https://httpd.apache.org/security/vulnerabilities_24.html,URL-https://github.c
                                                                           om/RootUp/PersonalStuff/blob/master/http-vuln-cve-2021-41773.nse

msf6 auxiliary(scanner/http/apache_normalize_path) > 
```
