## Vulnerable Application

This module will enumerate all installed applications on a Windows system that
are installed with Chocolatey.

## Verification Steps
  1. Start msfconsole
  2. Get meterpreter or shell session
  3. Do: `use post/windows/gather/enum_chocolatey_applications`
  4. Do: `set SESSION <session id>`
  5. Do: `run`

## Options

### ChocoPath

This is here for the incredibly rare cases where chocolatey is not on the
system path. It allows you to set the path of the chocolatey executable
ahead of time. Unless this is changed, it assumes to use chocolatey from
the path.

## Scenarios

### Windows 10 Pro (21H2 Build 19044.1586).

```
msf6 exploit(multi/handler) > [*] Meterpreter session 12 opened (192.168.56.1:4444 -> 192.168.56.112:49906 ) at 2022-03-27 15:57:39 -0400

msf6 exploit(multi/handler) > use post/windows/gather/enum_chocolatey_applications 
msf6 post(windows/gather/enum_chocolatey_applications) > set SESSION 12
SESSION => 12
msf6 post(windows/gather/enum_chocolatey_applications) > run

[*] Enumerating applications installed on DESKTOP-LB04G7R
[*] Targets Chocolatey version: 1.0.0
[*] Getting chocolatey applications.
[+] Successfully grabbed all items
Installed Chocolatey Applications
=================================

Name                       Version
----                       -------
GoogleChrome               99.0.4844.82
SQLite                     3.38.1
chocolatey                 1.0.0
chocolatey-core.extension  1.3.5.1
notepadplusplus            8.3.3
notepadplusplus.install    8.3.3
sublimetext3               3.2.2

[+] Results stored in: /home/rad10/.msf4/loot/20220327160034_default_192.168.56.112_host.application_704988.txt
[*] Post module execution completed
```
