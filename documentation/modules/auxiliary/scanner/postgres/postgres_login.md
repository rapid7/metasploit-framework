## Description

This auxiliary module is a brute-force login tool for Postgres servers.

## Verification Steps

1. Do: `use auxiliary/scanner/postgres/postgres_login`
2. Do: `set PASS_FILE [file containing passwords]`
3. Do: `set RHOSTS [IP]`
4. Do: `set USER_FILE [file containing usernames]`
5. Do: `set DATABASE [template name]`
6. Do: `run`

The above USER_FILE and PASS_FILE options can be replaced with USERNAME
and PASSWORD if you know the credentials.

## Getting an Interactive Session

The CreateSession option allows you to obtain an interactive session
for the Postgres client you're connecting to. The run command with CreateSession
set to true should give you an interactive session.

For example:

```msf
msf6 auxiliary(scanner/postgres/postgres_login) > run rhost=127.0.0.1 rport=5432 username=postgres password=password database=template1 createsession=true
```

Should yield:

```msf
[+] 127.0.0.1:5432 - Login Successful: postgres:password@template1
[*] PostgreSQL session 1 opened (127.0.0.1:61324 -> 127.0.0.1:5432) at 2024-03-15 14:00:12 -0500
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

You can interact with your session using `sessions -i -1` or `sessions <session id>`.
Use the help command for more info.

```msf
msf6 auxiliary(scanner/postgres/postgres_login) > sessions

Active sessions
===============

  Id  Name  Type        Information                           Connection
  --  ----  ----        -----------                           ----------
  1         postgresql  PostgreSQL postgres @ 127.0.0.1:5432  127.0.0.1:61324 -> 127.0.0.1:5432 (127.0.0.1)

msf6 auxiliary(scanner/postgres/postgres_login) > sessions -i 1
[*] Starting interaction with 1...
```

When interacting with a session, the help command can be useful:

```msf
postgresql @ 127.0.0.1:5432 (template1) > help

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


PostgreSQL Client Commands
==========================

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

  auxiliary/admin/postgres/postgres_readfile
  auxiliary/admin/postgres/postgres_sql
  auxiliary/scanner/postgres/postgres_hashdump
  auxiliary/scanner/postgres/postgres_schemadump
  auxiliary/scanner/postgres/postgres_version
  exploit/linux/postgres/postgres_payload
  exploit/multi/postgres/postgres_copy_from_program_cmd_exec
  exploit/multi/postgres/postgres_createlang
  exploit/windows/postgres/postgres_payload
```

Once you've done that, you can run any Postgres query against the target using the `query` command:

```msf
postgresql @ 127.0.0.1:5432 (template1) > query -h
Usage: query

Run a single SQL query on the target.

OPTIONS:

    -h, --help      Help menu.
    -i, --interact  Enter an interactive prompt for running multiple SQL queries

Examples:

    query SELECT user;
    query SELECT version();
    query SELECT * FROM pg_catalog.pg_tables;

postgresql @ 127.0.0.1:5432 (template1) > query 'SELECT version();'
[*] SELECT 1

Response
========

    #  version
    -  -------
    0  PostgreSQL 14.1 on aarch64-apple-darwin20.6.0, compiled by Apple clang version 12.0.5 (clang-1205.0.22.9), 64-bit
```

Alternatively you can enter a SQL prompt via the `query_interactive` command which supports multiline commands:

```msf
postgresql @ 127.0.0.1:5432 (template1) > query_interactive -h
Usage: query_interactive

Go into an interactive SQL shell where SQL queries can be executed.
To exit, type 'exit', 'quit', 'end' or 'stop'.

postgresql @ 127.0.0.1:5432 (template1) > query_interactive
[*] Starting interactive SQL shell for postgresql @ 127.0.0.1:5432 (template1)
[*] SQL commands ending with ; will be executed on the remote server. Use the exit command to exit.

SQL >> SELECT table_name
SQL *>   FROM information_schema.tables
SQL *>  LIMIT 2;
[*] Executing query: SELECT table_name FROM information_schema.tables LIMIT 2;
[*] SELECT 2

Response
========

    #  table_name
    -  ----------
    0  pg_statistic
    1  pg_type

SQL >>
```
