OWA (Outlook Webapp) is vulnerable to time-based user enumeration attacks.
This module leverages all known, and even some lesser-known services exposed by default
Exchange installations to enumerate email.

Error-based user enumeration for Office 365 integrated email addresses

## Verification

- Start `msfconsole`
- `use auxiliary/scanner/msmail/exchange_enum`
- `set (`EMAIL` or `EMAIL_FILE`)`
- `run`
- `creds`

*Results should look something like below if valid users were found:*

```
host      origin    service        public  private  realm  private_type
----      ------    -------        ------  -------  -----  ------------
<ip>      <ip>      443/tcp (owa)  chris@somecompany.com
```