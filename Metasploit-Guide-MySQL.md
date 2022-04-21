## MySQL

For instance, when running a MySQL target:

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
run mysql://known_user@192.168.222.1 threads=50 pass_file=./rockyou.txt
```

Brute-force credentials:

```
use auxiliary/scanner/mysql/mysql_login
run mysql://192.168.222.1 threads=50 user_file=./users.txt pass_file=./rockyou.txt
```

Brute-force credentials in a subnet:

```
use auxiliary/scanner/mysql/mysql_login
run cidr:/24:mysql://user:pass@192.168.222.0 threads=50
run cidr:/24:mysql://user@192.168.222.0 threads=50 pass_file=./rockyou.txt
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
