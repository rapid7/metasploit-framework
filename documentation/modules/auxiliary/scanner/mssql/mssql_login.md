## Vulnerable Application

This module simply queries the MSSQL instance for a specific user/pass (default is sa with blank).

### Setup
A docker container can be spun up with the following command to test this module:
`docker run -e 'ACCEPT_EULA=Y' -e 'MSSQL_SA_PASSWORD=N0tpassword!' -p 1433:1433 -d mcr.microsoft.com/mssql/server:2022-latest`

## Verification Steps
1. Start msfconsole
2. Do: `use scanner/mssql/mssql_login`
3. Do: `set RHOSTS [IP]`
4. Do: `run`
5. You should get a shell.

## Options

### USER_FILE

File containing users, one per line.

### PASS_FILE

File containing passwords, one per line

## Scenarios
```
msf > use scanner/mssql/mssql_login
msf6 auxiliary(scanner/mssql/mssql_login) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf6 auxiliary(scanner/mssql/mssql_login) > set password N0tpassword!
password => N0tpassword!
msf6 auxiliary(scanner/mssql/mssql_login) > options

Module options (auxiliary/scanner/mssql/mssql_login):

   Name                 Current Setting  Required  Description
   ----                 ---------------  --------  -----------
   ANONYMOUS_LOGIN      false            yes       Attempt to login with a blank username and password
   BLANK_PASSWORDS      true             no        Try blank passwords for all users
   BRUTEFORCE_SPEED     5                yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS         false            no        Try each user/password couple stored in the current database
   DB_ALL_PASS          false            no        Add all passwords in the current database to the list
   DB_ALL_USERS         false            no        Add all users in the current database to the list
   DB_SKIP_EXISTING     none             no        Skip existing credentials stored in the current database (Accepted: none, user, user&realm)
   PASSWORD             N0tpassword!     no        A specific password to authenticate with
   PASS_FILE                             no        File containing passwords, one per line
   RHOSTS               127.0.0.1        yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT                1433             yes       The target port (TCP)
   STOP_ON_SUCCESS      false            yes       Stop guessing when a credential works for a host
   TDSENCRYPTION        false            yes       Use TLS/SSL for TDS data "Force Encryption"
   THREADS              1                yes       The number of concurrent threads (max one per host)
   USERNAME             sa               no        A specific username to authenticate as
   USERPASS_FILE                         no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS         false            no        Try the username as the password for all users
   USER_FILE                             no        File containing usernames, one per line
   USE_WINDOWS_AUTHENT  false            yes       Use windows authentication (requires DOMAIN option set)
   VERBOSE              true             yes       Whether to print output for all attempts


View the full module info with the info, or info -d command.

msf6 auxiliary(scanner/mssql/mssql_login) > run

[*] 127.0.0.1:1433        - 127.0.0.1:1433 - MSSQL - Starting authentication scanner.
[!] 127.0.0.1:1433        - No active DB -- Credential data will not be saved!
[+] 127.0.0.1:1433        - 127.0.0.1:1433 - Login Successful: WORKSTATION\sa:N0tpassword!
[*] 127.0.0.1:1433        - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/mssql/mssql_login) >
```
