This module scans for Cambium ePMP 1000 management login portal(s), and attempts to identify valid credentials. Default login credentials are - admin/admin, installer/installer, home/home and readonly/readonly.

## Verification Steps

1. Do: ```auxiliary/scanner/http/epmp1000_web_login```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```run```

## Sample Output

  ```
msf > use auxiliary/scanner/http/epmp1000_web_login
msf auxiliary(epmp1000_web_login) > info

       Name: Cambium ePMP 1000 Login Scanner
     Module: auxiliary/scanner/http/epmp1000_web_login
    License: Metasploit Framework License (BSD)
       Rank: Normal

Provided by:
  Karn Ganeshen <KarnGaneshen@gmail.com>

Basic options:
  Name              Current Setting  Required  Description
  ----              ---------------  --------  -----------
  BLANK_PASSWORDS   false            no        Try blank passwords for all users
  BRUTEFORCE_SPEED  5                yes       How fast to bruteforce, from 0 to 5
  DB_ALL_CREDS      false            no        Try each user/password couple stored in the current database
  DB_ALL_PASS       false            no        Add all passwords in the current database to the list
  DB_ALL_USERS      false            no        Add all users in the current database to the list
  PASSWORD          admin            no        A specific password to authenticate with
  PASS_FILE                          no        File containing passwords, one per line
  Proxies                            no        A proxy chain of format type:host:port[,type:host:port][...]
  RHOSTS                             yes       The target address range or CIDR identifier
  RPORT             80               yes       The target port
  SSL               false            no        Negotiate SSL/TLS for outgoing connections
  STOP_ON_SUCCESS   false            yes       Stop guessing when a credential works for a host
  THREADS           1                yes       The number of concurrent threads
  USERNAME          admin            no        A specific username to authenticate as
  USERPASS_FILE                      no        File containing users and passwords separated by space, one pair per line
  USER_AS_PASS      false            no        Try the username as the password for all users
  USER_FILE                          no        File containing usernames, one per line
  VERBOSE           true             yes       Whether to print output for all attempts
  VHOST                              no        HTTP server virtual host

Description:
  This module scans for Cambium ePMP 1000 management login portal(s), 
  and attempts to identify valid credentials. Default login 
  credentials are - admin/admin, installer/installer, home/home and 
  readonly/readonly.

msf auxiliary(epmp1000_web_login) > set rhosts 1.2.3.4
msf auxiliary(epmp1000_web_login) > set username installer
msf auxiliary(epmp1000_web_login) > set password installer
msf auxiliary(epmp1000_web_login) > run

[+] 1.2.3.4:80 - Running Cambium ePMP 1000 version 3.0...
[*] 1.2.3.4:80 - Trying username:"installer" with password:"installer"
[+] SUCCESSFUL LOGIN - 1.2.3.4:80 - "installer":"installer"
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
  ```
