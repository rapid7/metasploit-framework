OWA (Outlook Webapp) is vulnerable to time-based user enumeration attacks.
 This module leverages all known, and even some lesser-known services exposed by default
 Exchange installations to enumerate users. It also targets Office 365 for error-based user enumeration.

- Error-based user enumeration for on premise Exchange services

**Note:**  Currently uses RHOSTS which resolves to an IP which is NOT desired, this is currently being fixed 

## Verification Steps

- Start `msfconsole`
- `use auxiliary/scanner/msmail/onprem_enum`
- `set RHOSTS <target>`
- `set (`USER` or `USER_FILE`)
- `run`
- `creds`

*Results should look something like below if valid users were found:*

```
host      origin    service        public  private  realm  private_type
----      ------    -------        ------  -------  -----  ------------
10.1.1.1  10.1.1.1  443/tcp (owa)
10.1.1.1  10.1.1.1  443/tcp (owa)  chris
```
