## Description

The `smb_enumshares` module, as would be expected, enumerates any SMB shares that are available on a remote system.
The module can also recursively go through each directory in each share and gather information about the files inside them.
On some systems such as Windows 7, it can also iterate over user directories and `%appdata%`.

## Verification Steps

1. Do: ```use auxiliary/scanner/smb/smb_enumshares```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set THREADS [number of threads]```
4. Do: ```run```

## Scenarios

### Uncredentialed - Windows 10 Target

```
msf6 auxiliary(scanner/smb/smb_enumshares) > set SpiderProfiles false
SpiderProfiles => false
msf6 auxiliary(scanner/smb/smb_enumshares) > set SpiderShares false
SpiderShares => false
msf6 auxiliary(scanner/smb/smb_enumshares) > set RHOSTS 192.168.129.131
RHOSTS => 192.168.129.131
msf6 auxiliary(scanner/smb/smb_enumshares) > run

[*] 192.168.129.131:139   - Starting module
[-] 192.168.129.131:139   - Login Failed: The SMB server did not reply to our request
[*] 192.168.129.131:445   - Starting module
[-] 192.168.129.131:445   - Login Failed: (0xc000006d) STATUS_LOGON_FAILURE: The attempted logon is invalid. This is either due to a bad username or authentication information.
[*] 192.168.129.131:      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Credentialed - Windows 10 Target

As you can see in the previous scan, access is denied to most of the systems that are probed.
Doing a Credentialed scan produces much different results.

```
msf6 auxiliary(scanner/smb/smb_enumshares) > set SMBPass simon
SMBPass => simon
msf6 auxiliary(scanner/smb/smb_enumshares) > set SMBUser simon
SMBUser => simon
msf6 auxiliary(scanner/smb/smb_enumshares) > run

[*] 192.168.129.131:139   - Starting module
[-] 192.168.129.131:139   - Login Failed: The SMB server did not reply to our request
[*] 192.168.129.131:445   - Starting module
[!] 192.168.129.131:445   - peer_native_os is only available with SMB1 (current version: SMB3)
[!] 192.168.129.131:445   - peer_native_lm is only available with SMB1 (current version: SMB3)
[+] 192.168.129.131:445   - ADMIN$ - (DISK) Remote Admin
[+] 192.168.129.131:445   - C$ - (DISK) Default share
[+] 192.168.129.131:445   - IPC$ - (IPC) Remote IPC
[+] 192.168.129.131:445   - MySharesOnWin10 - (DISK)
[+] 192.168.129.131:445   - print$ - (DISK) Printer Drivers
[+] 192.168.129.131:445   - TestPrinter - (PRINTER) Test Printer
[*] 192.168.129.131:      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
The disconnect on port 139 happens because Windows 10 uses SMB3, which operates on port 445 instead.
