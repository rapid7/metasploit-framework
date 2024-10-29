## Description
This module identifies the target host's PostgreSQL version. This occurs via the PostgreSQL API, which by default runs on port 5432.

## Vulnerable Application
### Installation of PostgreSQL on Kali Linux:
While many versions of Kali Linux come with a PostgreSQL installation out of the box, in the event that you are using a containerized Kali Linux
or other minimal installation, installation and setup of PostgreSQL is required.

The following instructions assume you are beginning with a fresh Kali installation as the root user.

1. `apt-get update`
2. `apt-get install postgresql`
3. `systemctl start postgresql`

At this point, PostgreSQL is installed and the installation has created the necessary user accounts to run the server.
This is where most users would begin the verification process. At this point, we'll setup a user account for use within the `postgres_version` module

4. `sudo --login --user postgres`
5. `psql`
6. `CREATE USER msf_documentation WITH PASSWORD 'msf_documentation'`

## Verification Steps
1. `use auxiliary/scanner/postgres/postgres_version`
2. `set RHOSTS [ips]`
3. `set RPORT [port]`
4. `set USERNAME [username]`
5. `set PASSWORD [password]`
6. `run`

## Scenarios
### PostgreSQL 10.4 on Kali Linux

```
msf > use auxiliary/scanner/postgres/postgres_version
msf auxiliary(scanner/postgres/postgres_version) > set RHOSTS 10.10.10.25
RHOSTS => 10.10.10.25
msf auxiliary(scanner/postgres/postgres_version) > set USERNAME msf_documentation
USERNAME => msf_documentation
msf auxiliary(scanner/postgres/postgres_version) > set PASSWORD msf_documentation
PASSWORD => msf_documentation
msf auxiliary(scanner/postgres/postgres_version) > run

[*] 10.10.10.25:5432 Postgres - Version PostgreSQL 10.4 (Debian 10.4-2) on x86_64-pc-linux-gnu, compiled by gcc (Debian 7.3.0-18) 7.3.0, 64-bit (Post-Auth)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

## Confirming
### [postgresql](https://www.postgresql.org/docs/10/static/functions-info.html)

```
# sudo --login --user postgres psql
psql (10.4 (Debian 10.4-2))
Type "help" for help.

postgres=# SELECT version();
                                                                   version
----------------------------------------------------------------------------------------------------------------------------
 Postgres - Version PostgreSQL 10.4 (Debian 10.4-2) on x86_64-pc-linux-gnu, compiled by gcc (Debian 7.3.0-18) 7.3.0, 64-bit
(1 row)

```
