This module tests credentials on Fortinet SSL VPN servers (FortiGate).

NOTE: This module is only executing when Fortinet SSL VPN Server is detected.
When the server cannot be verified the module stops working.
The realm/domain is used for every request when set.

The module supports IPv6 requests.
The module supports several hosts at the same time.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/fortinet_ssl_vpn```
2. Do: ```set RHOSTS [IP]```
3. Configure a user and password list by setting either `USERNAME`, `PASSWORD`, `USER_FILE`, or `PASS_FILE`.
4. Do: ```run```

## Scenarios

IP-Addresses have been masked with x

```
msf5 auxiliary(scanner/http/fortinet_ssl_vpn) > run

[+] xxxx:xxxx:xxxx:xxxx::4:443 - Server is responsive...
[+] xxxx:xxxx:xxxx:xxxx::4:443 - Application appears to be Fortinet SSL VPN. Module will continue.
[*] xxxx:xxxx:xxxx:xxxx::4:443 - Starting login brute force...
[*] xxxx:xxxx:xxxx:xxxx::4:443 - [1/1] - Trying username:"testuser" with password:"superpass"
[+] SUCCESSFUL LOGIN - "testuser":"superpass"
[!] No active DB -- Credential data will not be saved!
[*] Scanned 1 of 2 hosts (50% complete)
[+] xxx.xxx.xxx.xxx:443 - [1/1] - Server is responsive...
[+] xxx.xxx.xxx.xxx:443 - [1/1] - Application appears to be Fortinet SSL VPN. Module will continue.
[*] xxx.xxx.xxx.xxx:443 - [1/1] - Starting login brute force...
[*] xxx.xxx.xxx.xxx:443 - [1/1] - Trying username:"testuser" with password:"superpass"
[+] SUCCESSFUL LOGIN - "testuser":"superpass"
[!] No active DB -- Credential data will not be saved!
[*] Scanned 2 of 2 hosts (100% complete)
[*] Auxiliary module execution completed

```