The ipmi_version module is used to identify the version of the IPMI specification implemented by devices on a network.

## Target Devices

Any exposed device that implements the IPMI specification should work with this module. This is a recon module rather than an exploitation module.

## Verification Steps

Set RHOSTS to the target device or range and run:

```
msf > use auxiliary/scanner/ipmi/ipmi_version
msf auxiliary(ipmi_version) > set RHOSTS 192.168.1.2
RHOSTS => 192.168.1.2
msf auxiliary(ipmi_version) > run

[*] Sending IPMI requests to 192.168.1.2->192.168.1.2 (1 hosts)
[*] 192.168.1.2:623 - IPMI - Probe sent
[+] 192.168.1.2:623 - IPMI - IPMI-2.0 OEMID:180010 UserAuth(auth_msg, auth_user, non_null_user) PassAuth(password, md5, md2) Level(1.5, 2.0)

```
