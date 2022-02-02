This module scans for Cambium ePMP 1000 management login portal(s), and attempts to identify valid credentials.
Default login credentials are - admin/admin, installer/installer, home/home and readonly/readonly.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/epmp1000_web_login```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```run```

## Scenarios

  ```
msf > use auxiliary/scanner/http/epmp1000_web_login
msf auxiliary(epmp1000_web_login) > set rhosts 1.2.3.4
msf auxiliary(epmp1000_web_login) > set username installer
msf auxiliary(epmp1000_web_login) > set password installer
msf auxiliary(epmp1000_web_login) > run

[+] 1.2.3.4:80 - Running Cambium ePMP 1000 version 3.0...
[*] 1.2.3.4:80 - Trying username:"installer" with password:"installer"
[+] SUCCESSFUL LOGIN - 1.2.3.4:80 - "installer":"installer"
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
  ```
