## Vulnerable Application

This module simply queries the MSSQL instance for a specific user/pass (default is sa with blank). 

## Verification Steps
Example steps in this format (is also in the PR):

1. Start msfconsole
2. Do: ```use scanner/mssql/mssql_login```
3. Do: ```set RHOSTS [IP]```
4. Do: ```run```
5. You should get a shell.

## Options
A number of options interesting options without default values exist. They are as follows: 
   
   Name                 Current Setting  Required  Description
   ----                 ---------------  --------  -----------
   PASSWORD                              no        A specific password to authenticate with
   PASS_FILE                             no        File containing passwords, one per line
   RHOSTS                                yes       The target host(s),
   USERPASS_FILE                         no        File containing users and passwords separated by space, one pair per line
   USER_FILE                             no        File containing usernames, one per line

Options ending in _FILE are used by specifing a file location. For example, specifying the USER_FILE would happend as follows:

```
msf6 auxiliary(scanner/mssql/mssql_login) > set USER_FILE ./userfile
```


## Scenarios
Specific demo of using the module that might be useful in a real world scenario.
```
msf > use scanner/mssql/mssql_login
msf (auxiliary(scanner/mssql/mssql_login)) > set RHOSTS 178.33.113.209
msf (auxiliary(scanner/mssql/mssql_login)) > run 

[*] 59.36.92.188:1433     - 59.36.92.189:1433 - MSSQL - Starting authentication scanner.
[-] 59.36.92.188:1433     - 59.36.92.189:1433 - LOGIN FAILED: WORKSTATION\sa: (Unable to Connect: The connection with (59.36.92.188:1433) timed out.)
[*] 59.36.92.188:1433     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```