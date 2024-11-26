## Description

This module allows you to authenticate to Softing Secure Integration Server.

By default:
* Credentials are `admin:admin`.
* HTTP is TCP/8099 and HTTPS is TCP/443. Either one can be used, but the module defaults to TCP/8099.

There does not seem to be a limit to the number of times login attempts can be made.

## Vulnerable Application

This module was tested against version 1.22, installed on Windows Server 2019 Standard x64.

*1.22 Download*

https://industrial.softing.com/products/opc-opc-ua-software-platform/integration-platform/secure-integration-server.html

## Verification Steps

1. Start `msfconsole`
2. Do: `use auxiliary/scanner/http/softing_sis_login`
3. Do: `set RHOSTS <target_ip>` OR `set RHOSTS file:/path/to/targets/file` if against several targets
4. Do: Optional: `set SSL true` if necessary
5. Do: Optional: `set RPORT 443` if SSL is set
6. Do: `set USERNAME <username>` if necessary. Default is `admin`
7. Do: `set PASSWORD <password>` if necessary. Default is `admin`
8. Do: `run`

If running against several usernames: `set USER_FILE /path/to/usernames_file`
If using a wordlist (e.g. common passwords): `set PASS_FILE /path/to/passwords_file`

`USER_FILE` and `PASS_FILE` take priority over `USERNAME` and `PASSWORD`.

A `username:password` pair of credentials can be provided by doing `set USERPASS_FILE /path/to/userpass_file`.

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

### Several targets, using different usernames and passwords

In this scenario, we have several targets that have different usernames and passwords for each.
All the targets have the Softing Secure Integration Server login page enabled at TCP/8099.

Contents of `usernames.txt`:
```
admin
admin1
user
lowpriv
guest
```

Contents of `passwords.txt`:
```
admin
admin123
BadPass
GoodPass?
P@ssw0rd
user
pass
password
lowpriv
```

Contents of `targets.txt`:
```
192.168.50.71
192.168.50.119
192.168.50.206
```

Module output:
```
msf6 > use auxiliary/scanner/http/softing_sis_login
msf6 auxiliary(scanner/http/softing_sis_login) > set RHOSTS file:/home/ubuntu/Documents/targets.txt
RHOSTS => file:/home/ubuntu/Documents/targets.txt
msf6 auxiliary(scanner/http/softing_sis_login) > set USER_FILE ~/Documents/usernames.txt
USER_FILE => ~/Documents/usernames.txt
msf6 auxiliary(scanner/http/softing_sis_login) > set PASS_FILE ~/Documents/passwords.txt
PASS_FILE => ~/Documents/passwords.txt
msf6 auxiliary(scanner/http/softing_sis_login) > set VERBOSE false
VERBOSE => false
msf6 auxiliary(scanner/http/softing_sis_login) > run

[+] 192.168.50.71:8099 - Success: 'admin:P@ssw0rd'
[*] Scanned 1 of 3 hosts (33% complete)
[+] 192.168.50.119:8099 - Success: 'admin:admin'
[*] Scanned 2 of 3 hosts (66% complete)
[+] 192.168.50.206:8099 - Success: 'admin:pass123'
[+] 192.168.50.206:8099 - Success: 'admin1:admin123'
[*] Scanned 3 of 3 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/softing_sis_login) > 
```

Note that `VERBOSE` was set to `false` in this scenario to reduce amount of output on screen.
By default, `VERBOSE` is set to true, which also outputs failed login attempts.

`creds` output:

```
msf6 auxiliary(scanner/http/softing_sis_login) > creds
Credentials
===========

host            origin          service          public  private   realm  private_type  JtR Format
----            ------          -------          ------  -------   -----  ------------  ----------
192.168.50.71   192.168.50.71   8099/tcp (http)  admin   P@ssw0rd         Password      
192.168.50.119  192.168.50.119  8099/tcp (http)  admin   admin            Password      
192.168.50.206  192.168.50.206  8099/tcp (http)  admin   pass123          Password      
192.168.50.206  192.168.50.206  8099/tcp (http)  admin1  admin123         Password      

msf6 auxiliary(scanner/http/softing_sis_login) > 
```
