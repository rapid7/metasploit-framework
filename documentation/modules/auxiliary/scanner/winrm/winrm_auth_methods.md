## Description
This module sends a request to an HTTP/HTTPS service to see if it is a WinRM service. If it is a WinRM service, it also gathers the Authentication Methods supported.

## Verification Steps

1. Do: ```use auxiliary/scanner/winrm/winrm_auth_methods```
2. Do: ```set RHOSTS [IP]```
3. Do: ```run```

## Scenarios

```
msf > use auxiliary/scanner/winrm/winrm_auth_methods
msf auxiliary(scanner/winrm/winrm_auth_methods) > set RHOSTS 1.1.1.10
RHOSTS => 1.1.1.10
msf auxiliary(scanner/winrm/winrm_auth_methods) > run 

[+] 1.1.1.10:5985: Negotiate protocol supported
[+] 1.1.1.10:5985: Basic protocol supported
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/winrm/winrm_auth_methods) >
```
