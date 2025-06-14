## Vulnerable Application
Redis is an in-memory data structure project implementing a distributed, in-memory key-value
database with optional durability. Redis supports different kinds of abstract data structures,
such as strings, lists, maps, sets, sorted sets, HyperLogLogs, bitmaps, streams, and spatial indexes.

This module is login utility to find the password of the Redis server by bruteforcing the login portal.

A complete installation guide for Redis can be found [here](https://redis.io/topics/quickstart)

### Redis Authentication

Redis has several ways to support secure connections to the in-memory database:

* Prior to Redis 6, the `requirepass` directive could be set, setting a master password for all connections.
  This requires the usage of the `AUTH <password>` command before executing any commands on the cluster.
* After Redis 6, the `requirepass` directive sets a password for the default user `default`
  * The `AUTH` command now takes two arguments instead of one: `AUTH <username> <password>`
  * The `AUTH` command still accepts a single arguments, but defaults to the user `default`

## Setup

Run redis in docker without auth:

```
docker run --rm -p 6379:6379 redis
```

Optionally setting the default password for the implicit `default` username account, connect to the running Redis instance and set a password:

```
$ nc 127.0.0.1 6379
config set requirepass mypass
+OK
```

Optionally creating an enabled `test_user` user account with password `mypass` - if ACL is supported (Redis >= 6.0.0):

```
$ nc 127.0.0.1 6379
ACL SETUSER test_user allkeys on +@string +@set -SADD >mypass
```

Optionally creating a disabled `test_user_disabled` user account with password `mypass` - if ACL is supported (Redis >= 6.0.0):

```
$ nc 127.0.0.1 6379
ACL SETUSER test_user_disabled allkeys off +@string +@set -SADD >mypass
```

## Verification Steps
1. Do: `use auxiliary/scanner/redis/redis_login`
2. Do: `set RHOSTS [ips]`
3. Do: `set PASS_FILE /home/kali/passwords.txt`
4. Do: `run`

## Options

### PASS_FILE
The file containing a list of passwords to try logging in with.

## Scenarios

### Redis Version 6.0.10
```
msf6 > use scanner/redis/redis_login
msf6 auxiliary(scanner/redis/redis_login) > set RHOSTS 192.168.1.7
RHOSTS => 192.168.1.7
msf6 auxiliary(scanner/redis/redis_login) > set PASS_FILE /home/kali/Downloads/passwords.txt
PASS_FILE => /home/kali/Downloads/pass.txt
msf6 auxiliary(scanner/redis/redis_login) > run

[!] 192.168.1.7:6379      - No active DB -- Credential data will not be saved!
[-] 192.168.1.7:6379      - 192.168.1.7:6379      - LOGIN FAILED: redis:foobared (Incorrect: -WRONGPASS invalid username-password pair)
[-] 192.168.1.7:6379      - 192.168.1.7:6379      - LOGIN FAILED: redis:admin (Incorrect: -WRONGPASS invalid username-password pair)
[-] 192.168.1.7:6379      - 192.168.1.7:6379      - LOGIN FAILED: redis:administrator (Incorrect: -WRONGPASS invalid username-password pair)
[+] 192.168.1.7:6379      - 192.168.1.7:6379      - Login Successful: redis:mypass (Successful: +OK)
[*] 192.168.1.7:6379      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
