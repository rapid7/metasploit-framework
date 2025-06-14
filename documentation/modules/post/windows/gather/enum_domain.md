## Vulnerable Application

This module identifies the primary Active Directory domain name
and domain controller.

## Verification Steps

1. Start msfconsole
1. Get a session on a Windows target on a domain
1. Do: `use post/windows/gather/enum_domain`
1. Do: `set session [#]`
1. Do: `run`
1. You should receive Active Directory domain information

## Options

## Scenarios

### Windows 2016 with Windows 2008 SP1 DC

```
msf6 post(windows/gather/enum_domain) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > sysinfo
Computer        : WIN-7V3NGVNQTJ1
OS              : Windows 2016+ (10.0 Build 14393).
Architecture    : x64
System Language : en_US
Domain          : CORP
Logged On Users : 4
Meterpreter     : x64/windows
meterpreter > background
[*] Backgrounding session 1...

msf6 post(windows/gather/enum_domain) > use post/windows/gather/enum_domain
msf6 post(windows/gather/enum_domain) > set session 1
session => 1
msf6 post(windows/gather/enum_domain) > run

[+] Domain FQDN: corp.local
[+] Domain NetBIOS Name: CORP
[+] Domain Controller: WIN-17B09RRRJTG.corp.local (IP: 192.168.200.218)
[*] Post module execution completed
```
