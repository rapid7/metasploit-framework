## Overview
This module will start a process as another user using powershell.
By default, it will start an interactive cmd as the target user.

## Module Options
- **USER** - The use to run the program as. 
- **PASS** - The user's password  
- **DOMAIN** - The domain of the user
- **EXE** - The program to run (default cmd.exe)
- **ARGS** - The program arguments 
- **PATH** - The path to run the program in (default C:\\)
- **CHANNELIZE** - Channelize the output, required to read output or interact
- **INTERACT** - Interact with program
- **HIDDEN** - Hide the console window

## Module Process
The process will use the Start-Process command of powershell to run a process as another user.

## Limitations
- Requires Powershell
- Hidden Mode does not work with older powershell versions
- Interactive mode needs to be run from a meterpreter console
- Certain SYSTEM Services cannot run Start-Process with the -credential switch, causing the module to fail
- SYSTEM processes without I/O pipes cannot use interactive mode

## Examples

```
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > run post/windows/manage/run_as_psh user=test pass=mypassword

[*] Hidden mode may not work on older powershell versions, if it fails, try HIDDEN=false
[*] Process 1672 created.
[*] Channel 30 created.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\\>whoami
whoami
my-pc\test

C:\\>

meterpreter > run post/windows/manage/run_as_psh user=test pass=mypassword hidden=false channelize=false interactive=false exe=cmd path=C:\\\\windows args="/c start notepad"

[*] Process 9768 created.
meterpreter > 
```

