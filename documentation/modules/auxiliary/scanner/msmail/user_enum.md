OWA (Outlook Webapp) is vulnerable to time-based user enumeration attacks.
 This module leverages all known, and even some lesser-known services exposed by default
 Exchange installations to enumerate users. It also targets Office 365 for error-based user enumeration.

**Userenum (o365) Command**
- Error-based user enumeration for Office 365 integrated email addresses

**Note:**  Currently uses RHOSTS which resolves to an IP which is NOT desired, this is currently being fixed 

## Verification

- Start `msfconsole`
- `use auxiliary/scanner/msmail/user_enum`
- `set RHOSTS <target>`
- `set OnPrem true` and (set `USER` or `USER_FILE`) OR `set O365 true` and (set `EMAIL` or `EMAIL_FILE`)
- `run`
- `creds`

*Results should look something like below if valid users were found:*

```
host      origin    service        public  private  realm  private_type
----      ------    -------        ------  -------  -----  ------------
10.1.1.1  10.1.1.1  443/tcp (owa)
10.1.1.1  10.1.1.1  443/tcp (owa)  chris
```
