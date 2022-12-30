## Vulnerable Application

This module has been tested successfully against:
- Windows server 2019
- Windows server 2016
- Windows 10

### Description

The `smb_enumshares` module, as would be expected, enumerates any SMB shares that are available on a remote system.
The module can also recursively go through each directory in each share and gather information about the files inside them.
On some systems such as Windows 7, it can also iterate over user directories and `%appdata%`.

## Options

```
set RHOSTS [string]
```
This is the target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html for more information.

```
set SpiderProfiles [boolean]
```
This is used to enable the module to only spider user profiles when share is a disk share.

```
set SpiderShares [boolean]
```
This is used to enable the module to spider shares recursively.

```
set ShowFiles [boolean]
```
This is used to enable the module to show detailed information when spidering.

```
set Share [string]
```
Can be set to only enumerate over a specific share.

## Verification Steps

1. Do: `use auxiliary/scanner/smb/smb_enumshares`
2. Do: `set RHOSTS [IP]`
3. Do: `set THREADS [number of threads]`
4. Do: `run`

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

### Credentialed - Windows server 2019

This scenario makes use of the `Share` option, that is used to pass a specific share to be enumerated. The module is
also being ran with inline options in this scenario.

```
msf6 auxiliary(scanner/smb/smb_enumshares) > run smb://<Account>:<Password>@<TargetIP> spidershares=true showfiles=true share=<Share directory name>

[*] <TargetIP>   - Starting module
[-] <TargetIP>   - Login Failed: The SMB server did not reply to our request
[*] <TargetIP>   - Starting module
[!] <TargetIP>   - peer_native_os is only available with SMB1 (current version: SMB3)
[!] <TargetIP>   - peer_native_lm is only available with SMB1 (current version: SMB3)
[+] <TargetIP>   - my_share - (DISK)
[+] <TargetIP>   -  \\VB\my_share
==============

 Type  Name            Created                    Accessed                   Written                    Changed                    Size
 ----  ----            -------                    --------                   -------                    -------                    ----
 FILE  Passwords.txt   2022-10-12T11:41:51+01:00  2022-10-12T11:41:51+01:00  2022-10-12T11:41:51+01:00  2022-10-12T17:08:44+01:00  0
 FILE  paSsWords1.txt  2022-10-12T11:52:00+01:00  2022-10-12T11:52:00+01:00  2022-10-12T11:52:00+01:00  2022-10-12T17:08:59+01:00  0
 FILE  test.txt        2022-10-07T17:49:36+01:00  2022-10-07T17:49:36+01:00  2022-10-07T17:49:36+01:00  2022-10-07T17:49:39+01:00  0

[+] 192.168.175.129:445   - info saved in: /Users/<user>/.msf4/loot/20221026120037_default_192.168.175.129_smb.enumshares_935447.txt
[*] smb://<Account>:<Password>@<TargetIP>: - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
