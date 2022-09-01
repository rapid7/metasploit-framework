The ipmi_cipher_zero module is used to find IPMI 2.0-compatible systems that are vulnerable to an authentication bypass vulnerability through the use of IPMI cipher zero, which means no cipher is used at all.

## Vulnerable Devices

This is an error in the IPMI 2.0 specification itself, so any device BMC fully implementing IPMI 2.0 will possibly have the vulnerable non-cipher enabled.

## Verification Steps

Set RHOSTS to the target device or range and run:

```
msf > use auxiliary/scanner/ipmi/ipmi_cipher_zero
msf auxiliary(ipmi_cipher_zero) > set RHOSTS 192.168.1.2
RHOSTS => 192.168.1.2
msf auxiliary(ipmi_cipher_zero) > run

[*] Sending IPMI requests to 192.168.1.2->192.168.1.2 (1 hosts)
[*] 192.168.1.2:623 - IPMI - NOT VULNERABLE: Rejected cipher zero with error code 17

```
