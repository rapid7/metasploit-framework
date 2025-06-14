## Vulnerable Application

This module will enumerate configured and recently used file shares.

## Verification Steps

1. Start msfconsole
2. Get a session
3. Do: `use post/windows/gather/enum_shares`
4. Do: `set SESSION <session id>`
5. Do: `run`

## Options

### CURRENT

Enumerate currently configured shares (default: `true`)

### RECENT

Enumerate recently mapped shares (default: `true`)

### ENTERED

Enumerate recently entered UNC Paths in the Run Dialog (default: `true`)

## Scenarios

### Windows Server 2008 (x64)

```
msf6 > use post/windows/gather/enum_shares
msf6 post(windows/gather/enum_shares) > set session 1
session => 1
msf6 post(windows/gather/enum_shares) > run

[*] Running module against WIN-17B09RRRJTG (192.168.200.218)
[*] The following shares were found:
[*] 	Name: SYSVOL
[*] 	Path: C:\Windows\SYSVOL\sysvol
[*] 	Remark: Logon server share 
[*] 	Type: DISK
[*] 
[*] 	Name: NETLOGON
[*] 	Path: C:\Windows\SYSVOL\sysvol\corp.local\SCRIPTS
[*] 	Remark: Logon server share 
[*] 	Type: DISK
[*] 
[*] Recent mounts found:
[*] 	\\127.0.0.1\C$
[*] 
[*] Recent UNC paths entered in Run dialog found:
[*] 	\\10.1.1.100\
[*] 	\\127.0.0.1\C$
[*] 
[*] Post module execution completed
```
