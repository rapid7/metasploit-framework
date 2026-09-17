## Vulnerable Application

This module connects to a MongoDB instance and retrieves the server version
using the buildInfo command. Through MongoDB 8.0 this command requires no
authentication; MongoDB 8.1+ requires authentication for buildInfo, so the
module reports '8.1+' unless USERNAME is set, in which case it authenticates
and retrieves the actual version string.

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
1. Do: `use auxiliary/scanner/mongodb/mongodb_version`
1. Do: `set rhost [ip]`
1. Do: `run`
1. You should get a version back

## Options

## Scenarios

### MongoDB 3.6.23, 4.4.30, 5.0.33, 6.0.28, 7.0.43, 8.3.11 with and without Authentication

```
msf > use auxiliary/scanner/mongodb/mongodb_version
msf auxiliary(scanner/mongodb/mongodb_version) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf auxiliary(scanner/mongodb/mongodb_version) > run RPORT=27017
[*] 127.0.0.1:27017       - Negotiated wire protocol: OP_MSG
[+] 127.0.0.1:27017       - MongoDB version: 3.6.23
[*] 127.0.0.1:27017       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_version) > run RPORT=27018
[*] 127.0.0.1:27018       - Negotiated wire protocol: OP_MSG
[+] 127.0.0.1:27018       - MongoDB version: 4.4.30
[*] 127.0.0.1:27018       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_version) > run RPORT=27019
[*] 127.0.0.1:27019       - Negotiated wire protocol: OP_MSG
[+] 127.0.0.1:27019       - MongoDB version: 5.0.33
[*] 127.0.0.1:27019       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_version) > run RPORT=27020
[*] 127.0.0.1:27020       - Negotiated wire protocol: OP_MSG
[+] 127.0.0.1:27020       - MongoDB version: 6.0.28
[*] 127.0.0.1:27020       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_version) > run RPORT=27021
[*] 127.0.0.1:27021       - Negotiated wire protocol: OP_MSG
[+] 127.0.0.1:27021       - MongoDB version: 7.0.43
[*] 127.0.0.1:27021       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_version) > run RPORT=27022
[*] 127.0.0.1:27022       - Negotiated wire protocol: OP_MSG
[+] 127.0.0.1:27022       - MongoDB version: 8.3.11
[*] 127.0.0.1:27022       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_version) > run RPORT=27023 USERNAME=admin PASSWORD=adminpassword
[*] 127.0.0.1:27023       - Negotiated wire protocol: OP_MSG
[+] 127.0.0.1:27023       - MongoDB version: 3.6.23
[*] 127.0.0.1:27023       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_version) > run RPORT=27024 USERNAME=admin PASSWORD=adminpassword
[*] 127.0.0.1:27024       - Negotiated wire protocol: OP_MSG
[+] 127.0.0.1:27024       - MongoDB version: 4.4.30
[*] 127.0.0.1:27024       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_version) > run RPORT=27025 USERNAME=admin PASSWORD=adminpassword
[*] 127.0.0.1:27025       - Negotiated wire protocol: OP_MSG
[+] 127.0.0.1:27025       - MongoDB version: 5.0.33
[*] 127.0.0.1:27025       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_version) > run RPORT=27026 USERNAME=admin PASSWORD=adminpassword
[*] 127.0.0.1:27026       - Negotiated wire protocol: OP_MSG
[+] 127.0.0.1:27026       - MongoDB version: 6.0.28
[*] 127.0.0.1:27026       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_version) > run RPORT=27027 USERNAME=admin PASSWORD=adminpassword
[*] 127.0.0.1:27027       - Negotiated wire protocol: OP_MSG
[+] 127.0.0.1:27027       - MongoDB version: 7.0.43
[*] 127.0.0.1:27027       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_version) > run RPORT=27028 USERNAME=admin PASSWORD=adminpassword
[*] 127.0.0.1:27028       - Negotiated wire protocol: OP_MSG
[*] 127.0.0.1:27028       - buildInfo requires authentication; retrying with configured credentials
[+] 127.0.0.1:27028       - MongoDB version: 8.3.11
[*] 127.0.0.1:27028       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
