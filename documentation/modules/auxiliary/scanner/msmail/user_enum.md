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
- `creds` shows valid users
- **Verify** the result is as expected
