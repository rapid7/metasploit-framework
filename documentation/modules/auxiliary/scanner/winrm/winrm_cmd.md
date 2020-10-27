## Description
This module runs arbitrary Windows commands using the WinRM Service. It needs login credentials to do so.

## Verification Steps

1. Do: ```use auxiliary/scanner/winrm/winrm_cmd```
2. Do: ```set CMD [WINDOWS COMMAND]```
3. Do: ```set RHOSTS [IP]```
4. Do: ```set USERNAME [USERNAME]```
5. Do: ```set PASSWORD [PASSWORD]```
6. Do: ```run```

## Scenarios

```
msf > use auxiliary/scanner/winrm/winrm_cmd
msf auxiliary(scanner/winrm/winrm_cmd) > set CMD hostname
CMD => hostname
msf auxiliary(scanner/winrm/winrm_cmd) > set RHOSTS 1.1.1.10
RHOSTS => 1.1.1.10
msf auxiliary(scanner/winrm/winrm_cmd) > set USERNAME Administrator
USERNAME => Administrator
msf auxiliary(scanner/winrm/winrm_cmd) > set PASSWORD vagrant 
PASSWORD => vagrant
msf auxiliary(scanner/winrm/winrm_cmd) > run 

[+] vagrant-2008R2

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

msf auxiliary(scanner/winrm/winrm_cmd) > 
```

