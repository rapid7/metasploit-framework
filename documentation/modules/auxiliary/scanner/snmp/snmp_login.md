## Vulnerable Application

  Installation instructions for SNMP server can be found for every operating system.
  The [Ubuntu 14.04](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-an-snmp-daemon-and-client-on-ubuntu-14-04) instructions can be used as an example for installing and configuring NFS.  The
  following was done on Kali linux:
  
  1. `sudo apt-get install snmpd`
  2. Set SNMP to listen on non-localhost: `nano /etc/snmp/snmpd.conf`
  ```
    #  Listen for connections from the local system only
    #agentAddress  udp:127.0.0.1:161
    #  Listen for connections on all interfaces (both IPv4 *and* IPv6)
    agentAddress udp:161,udp6:[::1]:161
  ```
  3. Restart the service: `service snmpd restart`

### SNMP Versions

SNMP has 3 main versions.
* **1**, **2c**: both use simple password protection (string), and are often defaulted to `public` (read only), and `private` (read/write).  Version 2 is backwards compatible with version 1.  This is a plaintext protocol and is vulenrable to being intercepted.
* **3**: has several security levels and is significantly more complex, but also not covered in this module.

## Verification Steps

  1. Install and configure SNMP
  2. Start msfconsole
  3. Do: `use auxiliary/scanner/snmp/snmp_login`
  4. Do: `run`

## Scenarios

  A run against the configuration from these docs

  ```
    msf > use auxiliary/scanner/snmp/snmp_login 
    msf auxiliary(snmp_login) > set rhosts 127.0.0.1
    rhosts => 127.0.0.1
    msf auxiliary(snmp_login) > run
    
    [!] No active DB -- Credential data will not be saved!
    [+] 127.0.0.1:161 - LOGIN SUCCESSFUL: public (Access level: read-only); Proof (sysDescr.0): Linux hostname 4.9.0-kali1-amd64 #1 SMP Debian 4.9.6-3kali2 (2017-01-30) x86_64
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed
  ```
  
  Another example can be found at this [source](http://bitvijays.github.io/blog/2016/03/03/learning-from-the-field-basic-network-hygiene/):
  
  ```
    [+] 10.4.xx.xx:161 - LOGIN SUCCESSFUL: public (Access level: read-only); Proof (sysDescr.0): Cisco IOS Software, C1130 Software (C1130-K9W7-M), Version 12.4(10b)JA, RELEASE SOFTWARE (fc2)
    Technical Support: http://www.cisco.com/techsupport
    Copyright (c) 1986-2007 by Cisco Systems, Inc.
    Compiled Wed 24-Oct-07 15:17 by prod_rel_team
    [*] Scanned 12 of 58 hosts (20% complete)
    [*] Scanned 18 of 58 hosts (31% complete)
    [+] 10.10.xx.xx:161 - LOGIN SUCCESSFUL: public (Access level: read-only); Proof (sysDescr.0): Digi Connect ME Version 82000856_F6 07/21/2006
    [+] 10.10.xx.xx:161 - LOGIN SUCCESSFUL: public (Access level: read-only); Proof (sysDescr.0): Digi Connect ME Version 82000856_F6 07/21/2006
    [*] Scanned 24 of 58 hosts (41% complete)
    [+] 10.11.xx.xx:161 - LOGIN SUCCESSFUL: private (Access level: read-write); Proof (sysDescr.0): ExtremeXOS version 12.2.2.11 v1222b11 by release-manager on Mon Mar 23 17:54:47 PDT 2009
    [+] 10.11.xx.xx:161 - LOGIN SUCCESSFUL: public (Access level: read-only); Proof (sysDescr.0): ExtremeXOS version 12.2.2.11 v1222b11 by release-manager on Mon Mar 23 17:54:47 PDT 2009
    [+] 10.11.xx.xx:161 - LOGIN SUCCESSFUL: private (Access level: read-write); Proof (sysDescr.0): ExtremeXOS version 12.2.2.11 v1222b11 by release-manager on Mon Mar 23 17:54:47 PDT 2009
    [+] 10.11.xx.xx:161 - LOGIN SUCCESSFUL: public (Access level: read-only); Proof (sysDescr.0): ExtremeXOS version 12.2.2.11 v1222b11 by release-manager on Mon Mar 23 17:54:47 PDT 2009
    [+] 10.11.xx.xx:161 - LOGIN SUCCESSFUL: private (Access level: read-write); Proof (sysDescr.0): ExtremeXOS version 12.2.2.11 v1222b11 by release-manager on Mon Mar 23 17:54:47 PDT 2009
    [+] 10.11.xx.xx:161 - LOGIN SUCCESSFUL: public (Access level: read-only); Proof (sysDescr.0): ExtremeXOS version 12.2.2.11 v1222b11 by release-manager on Mon Mar 23 17:54:47 PDT 2009
    [*] Scanned 29 of 58 hosts (50% complete)
    [*] Scanned 35 of 58 hosts (60% complete)
    [*] Scanned 41 of 58 hosts (70% complete)
    [*] Scanned 47 of 58 hosts (81% complete)
    [+] 10.25.xx.xx:161 - LOGIN SUCCESSFUL: public (Access level: read-only); Proof (sysDescr.0): Digi Connect ME Version 82000856_F6 07/21/2006
  ```

## Confirming

Since SNMP has been around for quite a while, there are many tools which can also be used to verify this configuration issue.
The following are other industry tools which can also be used.

### [nmap](https://nmap.org/nsedoc/scripts/snmp-info.html)

```
nmap -p 161 -sU --script=snmp-info 127.0.0.1

Starting Nmap 7.40 ( https://nmap.org ) at 2017-02-12 23:00 EST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00017s latency).
PORT    STATE SERVICE
161/udp open  snmp
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: 54ad55664725a15800000000
|   snmpEngineBoots: 2
|_  snmpEngineTime: 31m30s

Nmap done: 1 IP address (1 host up) scanned in 0.38 seconds
```
