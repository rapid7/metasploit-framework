## Overview

This post-exploitation module enables you to add a sysadmin to local SQL Server instances, use that login to collect and gather data, and remove the login from the system. 

Pre-2008 versions of MSSQL servers automatically granted local sysadmins admin rights. This changed in MSSQL Server 2008, but there are still ways around to get around it, thanks to this module! If you are able to get domain admin privileges, you'll be able to add yourself to the database domain group and access the server with your newly added account. 

## Basic Workflow


1. Get a Meterpreter session using a module like psexec. 
2. Create a syadmin login on the SQL server.
3. Log into SQL Server with the newly created login. 
4. Find and collect data from the server using a module like Microsoft SQL Server Find and Sample Data.
5. Remove the sysadmin login when you are done. 


## Options

The following options are required:

- **DB_PASSWORD** - This option sets the password for the new sysadmin login.
- **DB_USERNAME** - This option sets the name for the new sysadmin login. 
- **REMOVE_LOGIN** - This option removes DB_USERNAME from the database. 
- **SESSION** - This option sets the session that you want to use to run this module against. 

## Scenarios

Here's an example of how you can use this module:

```
meterpreter > use post/windows/manage/mssql_local_auth_bypass
meterpreter > set DB_USERNAME tacocat
meterpreter > set DB_PASSWORD 12345
meterpreter > set SESSION 1
meterpreter > exploit
```

 