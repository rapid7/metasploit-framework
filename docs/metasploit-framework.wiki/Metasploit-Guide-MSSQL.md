## MSSQL Workflows

Microsoft SQL Server (MSSQL) is a relational database management system. Commonly used in conjunction with web applications
and other software that need to persist data. MSSQL is a useful target for data extraction and code execution.

MSSQL is frequently found on port on the following ports:

- 1433/TCP
- 1434/UDP

### Lab Environment

Environment setup:

- Either follow [Microsoft's SQL Server installation guide](https://learn.microsoft.com/en-us/sql/database-engine/install-windows/install-sql-server?view=sql-server-ver16) or use chocolatey package manager 
- Enable TCP access within the SQL Server Configuration Manager
- Optional: [Microsoft's sqlcmd utility](https://docs.microsoft.com/en-us/sql/tools/sqlcmd-utility?view=sql-server-ver16) can be installed separately for querying the database from your host machine
- Optional: [Configure Windows firewall](https://learn.microsoft.com/en-us/sql/sql-server/install/configure-the-windows-firewall-to-allow-sql-server-access?view=sql-server-ver16) to allow MSSQL server access 

### MSSQL Enumeration

### Running queries

```
use auxiliary/admin/mssql/mssql_sql
run rhost=192.168.123.13 username=administrator password=p4$$w0rd sql='select auth_scheme from sys.dm_exec_connections where session_id=@@spid'
```

### Logging in and obtaining a session
To log in or obtain an interactive session on an MSSQL instance running on the target, use mssql_login

```msf
use auxiliary/scanner/mssql_login
run CreateSession=true RPORT=1433 RHOSTS=192.168.2.242 USERNAME=user PASSWORD=password
```

The CreateSession option, when set to true, will result in returning an interactive MSSQL session with the target machine
on a successful login:

```msf
[*] 192.168.2.242:1433    - 192.168.2.242:1433 - MSSQL - Starting authentication scanner.
[!] 192.168.2.242:1433    - No active DB -- Credential data will not be saved!
[+] 192.168.2.242:1433    - 192.168.2.242:1433 - Login Successful: WORKSTATION\user:password
[*] MSSQL session 1 opened (192.168.2.1:60963 -> 192.168.2.242:1433) at 2024-03-15 13:41:31 -0500
[*] 192.168.2.242:1433    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Which you can interact with using `sessions -i <session id>` or `sessions -1` to interact with the most recently opened session.

```msf
msf6 auxiliary(scanner/mssql/mssql_login) > sessions

Active sessions
===============

  Id  Name  Type   Information                     Connection
  --  ----  ----   -----------                     ----------
  1         mssql  MSSQL test @ 192.168.2.242:143  192.168.2.1:60963 -> 192.168.2
                   3                               .242:1433 (192.168.2.242)

msf6 auxiliary(scanner/mssql/mssql_login) > sessions -i 1
[*] Starting interaction with 1...

mssql @ 192.168.2.242:1433 (master) > query 'select @@version;'
Response
========

    #  NULL
    -  ----
    0  Microsoft SQL Server 2022 (RTM) - 16.0.1000.6 (X64)
	    Oct 8 2022 05:58:25
	    Copyright (C) 2022 Microsoft Corporation
	    Developer Edition (64-bit) on Windows Server 2022 Stand
       ard 10.0 <X64> (Build 20348: ) (Hypervisor)
```

When interacting with a session, the help command can be useful:

```msf
mssql @ 192.168.2.242:1433 (master) > help

Core Commands
=============

    Command            Description
    -------            -----------
    ?                  Help menu
    background         Backgrounds the current session
    bg                 Alias for background
    exit               Terminate the PostgreSQL session
    help               Help menu
    irb                Open an interactive Ruby shell on the current session
    pry                Open the Pry debugger on the current session
    sessions           Quickly switch to another session


MSSQL Client Commands
=====================

    Command            Description
    -------            -----------
    query              Run a single SQL query
    query_interactive  Enter an interactive prompt for running multiple SQL queri
                       es


Local File System Commands
==========================

    Command            Description
    -------            -----------
    getlwd             Print local working directory (alias for lpwd)
    lcat               Read the contents of a local file to the screen
    lcd                Change local working directory
    ldir               List local files (alias for lls)
    lls                List local files
    lmkdir             Create new directory on local machine
    lpwd               Print local working directory

This session also works with the following modules:

  auxiliary/admin/mssql/mssql_enum
  auxiliary/admin/mssql/mssql_escalate_dbowner
  auxiliary/admin/mssql/mssql_escalate_execute_as
  auxiliary/admin/mssql/mssql_exec
  auxiliary/admin/mssql/mssql_findandsampledata
  auxiliary/admin/mssql/mssql_idf
  auxiliary/admin/mssql/mssql_sql
  auxiliary/admin/mssql/mssql_sql_file
  auxiliary/scanner/mssql/mssql_hashdump
  auxiliary/scanner/mssql/mssql_schemadump
  exploit/windows/mssql/mssql_payload
```

To interact directly with the session as if in a SQL prompt, you can use the `query` command.

```msf
msf6 auxiliary(scanner/mssql/mssql_login) > sessions -i -1
[*] Starting interaction with 2...

mssql @ 192.168.2.242:1433 (master) > query -h
Usage: query

Run a single SQL query on the target.

OPTIONS:

    -h, --help      Help menu.
    -i, --interact  Enter an interactive prompt for running multiple SQL queries

Examples:

    query select @@version;
    query select user_name();
    query select name from master.dbo.sysdatabases;

mssql @ 192.168.2.242:1433 (master) > query 'select @@version;'
Response
========

    #  NULL
    -  ----
    0  Microsoft SQL Server 2022 (RTM) - 16.0.1000.6 (X64)
	Oct  8 2022 05:58:25
	Copyright (C) 2022 Microsoft Corporation
	Developer Edition (64-bit) on Windows Server 2022 Standard 10.0 <X64> (B
       uild 20348: ) (Hypervisor)
```

Alternatively you can enter a SQL prompt via the `query_interactive` command which supports multiline commands:

```msf
mssql @ 192.168.2.242:1433 (master) > query_interactive -h
Usage: query_interactive

Go into an interactive SQL shell where SQL queries can be executed.
To exit, type 'exit', 'quit', 'end' or 'stop'.

mssql @ 192.168.2.242:1433 (master) > query_interactive
[*] Starting interactive SQL shell for mssql @ 192.168.2.242:1433 (master)
[*] SQL commands ending with ; will be executed on the remote server. Use the exit command to exit.

SQL >> select top 2 table_catalog, table_schema
SQL *> from information_schema.tables;
[*] Executing query: select top 2 table_catalog, table_schema from information_schema.tables;
Response
========

    #  table_catalog  table_schema
    -  -------------  ------------
    0  master         dbo
    1  master         dbo

SQL >>
```

### Link crawling

Identify if the SQL server has been configured with trusted links, which allows running queries on other MSSQL instances:

```
use windows/mssql/mssql_linkcrawler
run rhost=192.168.123.13 username=administrator password=p4$$w0rd
```

### Kerberos Authentication

Details on the Kerberos specific option names are documented in [[Kerberos Service Authentication|kerberos/service_authentication]]

Connect to a Microsoft SQL Server instance and run a query:

```msf
msf6 > use auxiliary/admin/mssql/mssql_sql
msf6 auxiliary(admin/mssql/mssql_sql) > run 192.168.123.13 domaincontrollerrhost=192.168.123.13 username=administrator password=p4$$w0rd mssql::auth=kerberos mssql::rhostname=dc3.demo.local mssqldomain=demo.local sql='select auth_scheme from sys.dm_exec_connections where session_id=@@spid'
[*] Reloading module...
[*] Running module against 192.168.123.13

[*] 192.168.123.13:1433 - 192.168.123.13:88 - Valid TGT-Response
[+] 192.168.123.13:1433 - 192.168.123.13:88 - Valid TGS-Response
[*] 192.168.123.13:1433 - 192.168.123.13:88 - TGS MIT Credential Cache saved to ~/.msf4/loot/20220630193907_default_192.168.123.13_windows.kerberos_556101.bin
[*] 192.168.123.13:1433 - SQL Query: select auth_scheme from sys.dm_exec_connections where session_id=@@spid
[*] 192.168.123.13:1433 - Row Count: 1 (Status: 16 Command: 193)

 auth_scheme
 -----------
 KERBEROS

[*] Auxiliary module execution completed
```
