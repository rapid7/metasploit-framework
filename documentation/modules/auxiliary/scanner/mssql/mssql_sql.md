## Description

This module allows you to perform SQL queries against a database using known-good credentials.

## Verification Steps

1. Do: ```use auxiliary/scanner/mssql/mssql_sql```
2. Do: ```set PASSWORD [password1]```
3. Do: ```set RHOSTS [IP]```
4. Do: ```set [SQL Command]```
5. Do: ```run```

## Scenarios

```
msf > use auxiliary/admin/mssql/mssql_sql
msf auxiliary(mssql_sql) > set PASSWORD password1
PASSWORD => password1
msf auxiliary(mssql_sql) > set RHOST 192.168.1.195
RHOST => 192.168.1.195
msf auxiliary(mssql_sql) > set SQL use logins;select * from userpass
SQL => use logins;select * from userpass
msf auxiliary(mssql_sql) > run

[*] SQL Query: use logins;select * from userpass
[*] Row Count: 3 (Status: 16 Command: 193)



 userid  username  password
 ------  --------  --------
 1       bjohnson  password
 2       aadams    s3cr3t
 3       jsmith    htimsj

[*] Auxiliary module execution completed
msf auxiliary(mssql_sql) >
```
