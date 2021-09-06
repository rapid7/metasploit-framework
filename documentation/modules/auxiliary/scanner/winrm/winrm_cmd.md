## Description
This module runs a command over the WinRM protocol. It needs login credentials to do so.

## Verification Steps

1. Do: ```use auxiliary/scanner/winrm/winrm_cmd```
1. Do: ```set RHOSTS [IP]```
1. Do: ```set USERNAME [USERNAME]```
1. Do: ```set PASSWORD [PASSWORD]```
1. Do: ```run```

## Scenarios


### Run single command

```
msf6 > use scanner/winrm/winrm_cmd
msf6 auxiliary(scanner/winrm/winrm_cmd) > set username Administrator
username => Administrator
msf6 auxiliary(scanner/winrm/winrm_cmd) > set password pass12345
password => pass12345
msf6 auxiliary(scanner/winrm/winrm_cmd) > set rhosts 192.168.1.205
rhosts => 192.168.1.205
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
