## Vulnerable Application

This module identifies the primary domain via the registry. The registry value used is: 
`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\DCName`.

## Verification Steps

1. Start msfconsole
1. Get a session on a Windows target on a domain
1. Do: `use post/windows/gather/enum_domain`
1. Do: `set session [#]`
1. Do: `run`
1. You should information on the computer's domain

## Options

## Scenarios

### Windows 2012 DC

```
msf6 post(windows/gather/enum_domain) > sessions -i 6
[*] Starting interaction with 6...

meterpreter > sysinfo
Computer        : DC1
OS              : Windows 2012 (6.2 Build 9200).
Architecture    : x64
System Language : en_US
Domain          : hoodiecola
Logged On Users : 4
Meterpreter     : x86/windows
meterpreter > background
[*] Backgrounding session 6...
msf6 post(windows/gather/enum_domain) > use post/windows/gather/enum_domain
msf6 post(windows/gather/enum_domain) > set session 6
session => 6
msf6 post(windows/gather/enum_domain) > run

[+] FOUND Domain: hoodiecola
[+] FOUND Domain Controller: dc1 (IP: 1.1.1.1)
[*] Post module execution completed
```
