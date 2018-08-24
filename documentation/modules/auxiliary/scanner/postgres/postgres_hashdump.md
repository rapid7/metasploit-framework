## Description
This module is used to access the password hashes in use within a PostgreSQL database.
This occurs via the PostgreSQL API, which by default runs on port 5432.
Access to the `pg_shadow` system catalog is usually restricted to database superusers only. 

## Vulnerable Application
### Installation of PostgreSQL on Kali Linux:
While many versions of Kali Linux come with a PostgreSQL installation out of the box, in the event that you
are using a containerized Kali Linux or other minimal installation, installation and setup of PostgreSQL is required.

The following instructions assume you are beginning with a fresh Kali installation as the root user.

1. `apt-get update`
2. `apt-get install postgresql`
3. `systemctl start postgresql`

At this point, PostgreSQL is installed and the installation has created the necessary user accounts to run the server.
This is where most users would begin the verification process. At this point, we'll setup a user account for use within the `postgres_hashdump` module

4. `sudo --login --user postgres`
5. `psql`
6. `CREATE USER msf_documentation_superuser WITH SUPERUSER PASSWORD 'msf_documentation_superuser'`

## Verification Steps
1. `use auxiliary/scanner/postgres/postgres_hashdump`
2. `set RHOSTS [ips]`
3. `set RPORT [port]`
4. `set USERNAME [username]`
5. `set PASSWORD [password]`
6. `run`

## Scenarios
### PostgreSQL 10.4 on Kali Linux
```
msf > use auxiliary/scanner/postgres/postgres_hashdump
msf auxiliary(scanner/postgres/postgres_hashdump) > set RHOSTS 10.10.10.25
RHOSTS => 10.10.10.25
msf auxiliary(scanner/postgres/postgres_hashdump) > set USERNAME msf_documentation_superuser
USERNAME => msf_documentation_superuser
msf auxiliary(scanner/postgres/postgres_hashdump) > set PASSWORD msf_documentation_superuser
PASSWORD => msf_documentation_superuser
msf auxiliary(scanner/postgres/postgres_hashdump) > run
[+] Query appears to have run successfully
[+] Postgres Server Hashes
======================

 Username                     Hash
 --------                     ----
 msf                          md5b08431efa0cd58b024f3af4acd6b9057
 msf_documentation_superuser  md5e7ce29c6b3acd4d39bec5e527da21aba
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

## Confirming
### [postgresql](https://www.postgresql.org/docs/8.3/static/view-pg-shadow.html)

```
# sudo --login --user postgres psql
psql (10.4 (Debian 10.4-2))
Type "help" for help.

postgres=# SELECT usename, passwd FROM pg_shadow;                                                        
           usename           |               passwd                
-----------------------------+-------------------------------------
 postgres                    | 
 msf                         | md5b08431efa0cd58b024f3af4acd6b9057
 msf_documentation_superuser | md5e7ce29c6b3acd4d39bec5e527da21aba
(4 rows)
```
