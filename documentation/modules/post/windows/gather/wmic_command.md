## Vulnerable Application

This module executes WMIC commands on the specified host.


## Verification Steps

1. Start msfconsole
1. Get a Meterpreter session on a Windows target
1. Do: `use post/windows/gather/wmic_command`
1. Do: `set session [#]`
1. Do: `set command [wmic command]`
1. Do: `run`
1. You should receive WMIC command output


## Options

### RESOURCE

Full path to resource file containing WMIC commands.

### COMMAND

WMIC command.


## Scenarios

### Windows Server 2008 SP1 (x64)

```
msf6 > use post/windows/gather/wmic_command
msf6 post(windows/gather/wmic_command) > set session 1
session => 1
msf6 post(windows/gather/wmic_command) > set command os
command => os
msf6 post(windows/gather/wmic_command) > run

[*] Running module against WIN-17B09RRRJTG (192.168.200.218)
[*] Running WMIC command: os
[*] Command output saved to: /root/.msf4/loot/20220922071306_default_192.168.200.218_host.command.wmi_789917.txt
[*] Post module execution completed
msf6 post(windows/gather/wmic_command) > cat /root/.msf4/loot/20220922071306_default_192.168.200.218_host.command.wmi_789917.txt
[*] exec: cat /root/.msf4/loot/20220922071306_default_192.168.200.218_host.command.wmi_789917.txt

BootDevice               BuildNumber  BuildType            Caption                                     CodeSet  CountryCode  CreationClassName      CSCreationClassName   CSDVersion      CSName           CurrentTimeZone  DataExecutionPrevention_32BitApplications  DataExecutionPrevention_Available  DataExecutionPrevention_Drivers  DataExecutionPrevention_SupportPolicy  Debug  Description  Distributed  EncryptionLevel  ForegroundApplicationBoost  FreePhysicalMemory  FreeSpaceInPagingFiles  FreeVirtualMemory  InstallDate                LargeSystemCache  LastBootUpTime             LocalDateTime              Locale  Manufacturer           MaxNumberOfProcesses  MaxProcessMemorySize  MUILanguages  Name                                                                                 NumberOfLicensedUsers  NumberOfProcesses  NumberOfUsers  OperatingSystemSKU  Organization  OSArchitecture  OSLanguage  OSProductSuite  OSType  OtherTypeDescription  PAEEnabled  PlusProductID  PlusVersionNumber  Primary  ProductType  QuantumLength  QuantumType  RegisteredUser  SerialNumber             ServicePackMajorVersion  ServicePackMinorVersion  SizeStoredInPagingFiles  Status  SuiteMask  SystemDevice             SystemDirectory      SystemDrive  TotalSwapSpaceSize  TotalVirtualMemorySize  TotalVisibleMemorySize  Version   WindowsDirectory  
\Device\HarddiskVolume1  6001         Multiprocessor Free  Microsoft� Windows Server� 2008 Enterprise  1252     1            Win32_OperatingSystem  Win32_ComputerSystem  Service Pack 1  WIN-17B09RRRJTG  600              TRUE                                       TRUE                               TRUE                             3                                      FALSE               FALSE        256              2                           507164              1354124                 1788752            20220722133039.000000+600                    20220922115509.500000+600  20220922211154.399000+600  0409    Microsoft Corporation  -1                    8589934464            {"en-US"}     Microsoft� Windows Server� 2008 Enterprise |C:\Windows|\Device\Harddisk0\Partition1                         47                 4              10                                64-bit          1033        274             18                                                                          TRUE     2            1              1            Windows User    92516-083-1766663-76902  1                        0                        1354124                  OK      274        \Device\HarddiskVolume1  C:\Windows\system32  C:                               2358168                 1046924                 6.0.6001  C:\Windows        

msf6 post(windows/gather/wmic_command) > 
```
