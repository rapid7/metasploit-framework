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

### CreateSession

When using the `scanner/mssql/mssql_login` module, the CreateSession option can be used to obtain an interactive
session within the MSSQL instance. Running the following commands with all other options set:

```msf
msf6 auxiliary(scanner/mssql/mssql_login) > run CreateSession=true RPORT=1433 RHOSTS=192.168.2.242 USERNAME=user PASSWORD=password
```

Should give you output containing:

```msf
[*] 192.168.2.242:1433    - 192.168.2.242:1433 - MSSQL - Starting authentication scanner.
[!] 192.168.2.242:1433    - No active DB -- Credential data will not be saved!
[+] 192.168.2.242:1433    - 192.168.2.242:1433 - Login Successful: WORKSTATION\user:password
[*] MSSQL session 1 opened (192.168.2.1:60963 -> 192.168.2.242:1433) at 2024-03-15 13:41:31 -0500
[*] 192.168.2.242:1433    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Which you can interact with using `sessions -i <session id>` or `sessions -i -1` to interact with the most recently opened session.

```msf
msf6 auxiliary(scanner/mssql/mssql_login) > sessions

Active sessions
===============

  Id  Name  Type   Information                      Connection
  --  ----  ----   -----------                      ----------
  1         mssql  MSSQL test @ 192.168.2.242:1433  192.168.2.1:60963 -> 192.168.2.242:1433 (192.168.2.242)

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

### USER_FILE

File containing users, one per line.

### PASS_FILE

File containing passwords, one per line

## Scenarios

```msf
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
