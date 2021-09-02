## Description
This module creates a WinRM command shell. It needs login credentials to do so.
The module launches powershell.exe and communicates with it over stdin/stdout/stderr.

## Verification Steps

1. Do: ```use auxiliary/scanner/winrm/winrm_cmd```
1. Do: ```set RHOSTS [IP]```
1. Do: ```set USERNAME [USERNAME]```
1. Do: ```set PASSWORD [PASSWORD]```
1. Optionally Do: ```set CreateSession false```
1. Optionally Do: ```set CMD [WINDOWS COMMAND]```
1. Do: ```run```

## Scenarios

### Create shell

```
msf6 > use scanner/winrm/winrm_cmd
msf6 auxiliary(scanner/winrm/winrm_cmd) > set username Administrator
username => Administrator
msf6 auxiliary(scanner/winrm/winrm_cmd) > set password pass12345
password => pass12345
msf6 auxiliary(scanner/winrm/winrm_cmd) > set rhosts 192.168.1.205
rhosts => 192.168.1.205
msf6 auxiliary(scanner/winrm/winrm_cmd) > run
[*] Command shell session 1 opened (WinRM) at 2021-09-02 20:26:41 +1000

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/winrm/winrm_cmd) > sessions 

Active sessions
===============

  Id  Name  Type           Information                                         Connection
  --  ----  ----           -----------                                         ----------
  1         shell windows  WinRM Administrator:pass12345 (VM01\Administrator)  WinRM (192.168.1.205)

msf6 auxiliary(scanner/winrm/winrm_cmd) > sessions 1
[*] Starting interaction with 1...

Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users\Administrator>
```

### Run single command (no shell)

```
msf6 > use scanner/winrm/winrm_cmd
msf6 auxiliary(scanner/winrm/winrm_cmd) > set username Administrator
username => Administrator
msf6 auxiliary(scanner/winrm/winrm_cmd) > set password pass12345
password => pass12345
msf6 auxiliary(scanner/winrm/winrm_cmd) > set rhosts 192.168.1.205
rhosts => 192.168.1.205
msf6 auxiliary(scanner/winrm/winrm_cmd) > set CreateSession false
CreateSession => false
msf6 auxiliary(scanner/winrm/winrm_cmd) > set cmd whoami /priv
cmd => whoami /priv
msf6 auxiliary(scanner/winrm/winrm_cmd) > run


PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled
[+] Results saved to /home/ubuntu/.msf4/loot/20210902203150_default_192.168.1.205_winrm.cmd_result_736891.txt
[*] Scanned 1 of 1 hosts (100% complete)
```
