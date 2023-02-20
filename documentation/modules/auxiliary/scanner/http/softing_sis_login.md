## Description

This module allows you to authenticate to Softing Secure Integration Server.

By default:
* Credentials are `admin:admin`.
* HTTP is TCP/8099 and HTTPS is TCP/443. Either one can be used, but the module defaults to TCP/8099.

## Vulnerable Application

This module was tested against version 1.22, installed on Windows Server 2019 Standard x64.

*1.22 Download*

https://industrial.softing.com/products/opc-opc-ua-software-platform/integration-platform/secure-integration-server.html

## Verification Steps

1. Start `msfconsole`
2. Do: `use auxiliary/scanner/http/softing_sis_login`
3. Do: `set RHOST <target_ip>`
4. Do: Optional: `set SSL true` if necessary
5. Do: Optional: `set RPORT 443` if SSL is set
6. Do: `set USERNAME <username>` if necessary. Default is `admin`
7. Do: `set PASSWORD <password>` if necessary. Default is `admin`
8. Do: `run`

## Scenarios
### Default

In this scenario, the default options were used.

```
msf6 > use auxiliary/scanner/http/softing_sis_login 
msf6 auxiliary(scanner/http/softing_sis_login) > set RHOSTS 192.168.50.119
RHOSTS => 192.168.50.119
msf6 auxiliary(scanner/http/softing_sis_login) > run

[+] 192.168.50.119:8099 - Success: 'admin:admin'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/softing_sis_login) > 
```

`creds` output:

```
msf6 auxiliary(scanner/http/softing_sis_login) > creds
Credentials
===========

host            origin          service          public  private  realm  private_type  JtR Format
----            ------          -------          ------  -------  -----  ------------  ----------
192.168.50.119  192.168.50.119  8099/tcp (http)  admin   admin           Password      

msf6 auxiliary(scanner/http/softing_sis_login) > 
```

### Different admin password, SSL in use

In this scenario, the default password for the `admin` user has been changed, and SSL was used.

```
msf6 > use auxiliary/scanner/http/softing_sis_login 
msf6 auxiliary(scanner/http/softing_sis_login) > set RHOSTS 192.168.50.119
RHOSTS => 192.168.50.119
msf6 auxiliary(scanner/http/softing_sis_login) > set PASSWORD admin123
PASSWORD => admin123
msf6 auxiliary(scanner/http/softing_sis_login) > set SSL true
[!] Changing the SSL option's value may require changing RPORT!
SSL => true
msf6 auxiliary(scanner/http/softing_sis_login) > set RPORT 443
RPORT => 443
msf6 auxiliary(scanner/http/softing_sis_login) > run

[+] 192.168.50.119:443 - Success: 'admin:admin123'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/softing_sis_login) > 
```

`creds` output:

```
msf6 auxiliary(scanner/http/softing_sis_login) > creds
Credentials
===========

host            origin          service          public  private  realm  private_type  JtR Format
----            ------          -------          ------  -------  -----  ------------  ----------
192.168.50.119  192.168.50.119  8099/tcp (http)  admin   admin           Password      
192.168.50.119  192.168.50.119  443/tcp (https)  admin   admin123        Password      

msf6 auxiliary(scanner/http/softing_sis_login) > 
```
