## Vulnerable Application

This module prints out the operating system environment variables.

## Verification Steps

1. Start msfconsole
1. Get a session
1. Do: `use post/multi/gather/env`
1. Do: `set SESSION <session id>`
1. Do: `run`

## Options

## Scenarios

### Windows 11 Pro (10.0.22000 N/A Build 22000)

```
msf6 > use post/multi/gather/env
msf6 post(multi/gather/env) > set session 1 
session => 1
msf6 post(multi/gather/env) > run

[*] Running module against WinDev2110Eval (192.168.200.140)
ALLUSERSPROFILE=C:\ProgramData
APPDATA=C:\Users\User\AppData\Roaming
CommonProgramFiles=C:\Program Files\Common Files
CommonProgramFiles(x86)=C:\Program Files (x86)\Common Files
CommonProgramW6432=C:\Program Files\Common Files
COMPUTERNAME=WINDEV2110EVAL
ComSpec=C:\Windows\system32\cmd.exe
DriverData=C:\Windows\System32\Drivers\DriverData
HOMEDRIVE=C:
HOMEPATH=\Users\User
LOCALAPPDATA=C:\Users\User\AppData\Local
LOGONSERVER=\\WINDEV2110EVAL
NUMBER_OF_PROCESSORS=2
OneDrive=C:\Users\User\OneDrive
OS=Windows_NT
Path=C:\Program Files (x86)\Common Files\Oracle\Java\javapath;C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Program Files\dotnet\;C:\Program Files\Microsoft SQL Server\130\Tools\Binn\;C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\;C:\Users\User\AppData\Local\Microsoft\WindowsApps;;C:\Users\User\AppData\Local\Programs\Microsoft VS Code\bin;C:\Users\User\.dotnet\tools
PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL
PROCESSOR_ARCHITECTURE=AMD64
PROCESSOR_IDENTIFIER=Intel64 Family 6 Model 26 Stepping 5, GenuineIntel
PROCESSOR_LEVEL=6
PROCESSOR_REVISION=1a05
ProgramData=C:\ProgramData
ProgramFiles=C:\Program Files
ProgramFiles(x86)=C:\Program Files (x86)
ProgramW6432=C:\Program Files
PROMPT=$P$G
PSExecutionPolicyPreference=Bypass
PSModulePath=C:\Users\User\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
PUBLIC=C:\Users\Public
SESSIONNAME=Console
SystemDrive=C:
SystemRoot=C:\Windows
TEMP=C:\Users\User\AppData\Local\Temp
TMP=C:\Users\User\AppData\Local\Temp
USERDOMAIN=WINDEV2110EVAL
USERDOMAIN_ROAMINGPROFILE=WINDEV2110EVAL
USERNAME=User
USERPROFILE=C:\Users\User
windir=C:\Windows
[+] Results saved to /root/.msf4/loot/20220731233101_default_192.168.200.140_windows.environm_058721.txt
[*] Post module execution completed
```
