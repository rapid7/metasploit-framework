## Vulnerable Application

This module attempts to brute force authentication credentials for MongoDB.
It supports both SCRAM-SHA-1 (MongoDB 3.0+) and falls back to legacy
MONGODB-CR authentication if SCRAM is unsupported by the target server.

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
1. Do: `use auxiliary/scanner/mongodb/mongodb_login`
1. Optionally Do: `set username <username>`
1. Optionally Do: `set password <password>`
1. Do: `set rhost [ip]`
1. Do: `run`
1. You should get a login

## Options

### AUTH_DB

Database to authenticate against. Defaults to `admin`

### USERNAME

Username for authentication. Defaults to ``

### PASSWORD

Password for authentication. Defaults to ``

## Scenarios

### MongoDB 3.6.23, 4.4.30, 5.0.33, 6.0.28, 7.0.43, 8.3.11 with and without Authentication

```
msf > use auxiliary/scanner/mongodb/mongodb_login
msf auxiliary(scanner/mongodb/mongodb_login) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf auxiliary(scanner/mongodb/mongodb_login) > run RPORT=27017
[*] 127.0.0.1:27017       - Scanning IP: 127.0.0.1
[*] 127.0.0.1:27017       - Negotiated wire protocol: OP_MSG
[+] 127.0.0.1:27017       - Mongo server 127.0.0.1 (version 3.6.23) doesn't use authentication
[*] 127.0.0.1:27017       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_login) > run RPORT=27018
[*] 127.0.0.1:27018       - Scanning IP: 127.0.0.1
[*] 127.0.0.1:27018       - Negotiated wire protocol: OP_MSG
[+] 127.0.0.1:27018       - Mongo server 127.0.0.1 (version 4.4.30) doesn't use authentication
[*] 127.0.0.1:27018       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_login) > run RPORT=27019
[*] 127.0.0.1:27019       - Scanning IP: 127.0.0.1
[*] 127.0.0.1:27019       - Negotiated wire protocol: OP_MSG
[+] 127.0.0.1:27019       - Mongo server 127.0.0.1 (version 5.0.33) doesn't use authentication
[*] 127.0.0.1:27019       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_login) > run RPORT=27020
[*] 127.0.0.1:27020       - Scanning IP: 127.0.0.1
[*] 127.0.0.1:27020       - Negotiated wire protocol: OP_MSG
[+] 127.0.0.1:27020       - Mongo server 127.0.0.1 (version 6.0.28) doesn't use authentication
[*] 127.0.0.1:27020       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_login) > run RPORT=27021
[*] 127.0.0.1:27021       - Scanning IP: 127.0.0.1
[*] 127.0.0.1:27021       - Negotiated wire protocol: OP_MSG
[+] 127.0.0.1:27021       - Mongo server 127.0.0.1 (version 7.0.43) doesn't use authentication
[*] 127.0.0.1:27021       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_login) > run RPORT=27022
[*] 127.0.0.1:27022       - Scanning IP: 127.0.0.1
[*] 127.0.0.1:27022       - Negotiated wire protocol: OP_MSG
[+] 127.0.0.1:27022       - Mongo server 127.0.0.1 (version 8.3.11) doesn't use authentication
[*] 127.0.0.1:27022       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_login) > run RPORT=27023 USERNAME=admin PASSWORD=adminpassword
[*] 127.0.0.1:27023       - Scanning IP: 127.0.0.1
[*] 127.0.0.1:27023       - Negotiated wire protocol: OP_MSG
[*] 127.0.0.1:27023       - Mongo server (version 3.6.23) requires authentication
[*] 127.0.0.1:27023       - Trying user: admin, password: adminpassword
[+] 127.0.0.1:27023       - 127.0.0.1 - SUCCESSFUL LOGIN 'admin' : 'adminpassword' (SCRAM-SHA-1)
[*] 127.0.0.1:27023       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_login) > run RPORT=27024 USERNAME=admin PASSWORD=adminpassword
[*] 127.0.0.1:27024       - Scanning IP: 127.0.0.1
[*] 127.0.0.1:27024       - Negotiated wire protocol: OP_MSG
[*] 127.0.0.1:27024       - Mongo server (version 4.4.30) requires authentication
[*] 127.0.0.1:27024       - Trying user: admin, password: adminpassword
[+] 127.0.0.1:27024       - 127.0.0.1 - SUCCESSFUL LOGIN 'admin' : 'adminpassword' (SCRAM-SHA-1)
[*] 127.0.0.1:27024       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_login) > run RPORT=27025 USERNAME=admin PASSWORD=adminpassword
[*] 127.0.0.1:27025       - Scanning IP: 127.0.0.1
[*] 127.0.0.1:27025       - Negotiated wire protocol: OP_MSG
[*] 127.0.0.1:27025       - Mongo server (version 5.0.33) requires authentication
[*] 127.0.0.1:27025       - Trying user: admin, password: adminpassword
[+] 127.0.0.1:27025       - 127.0.0.1 - SUCCESSFUL LOGIN 'admin' : 'adminpassword' (SCRAM-SHA-1)
[*] 127.0.0.1:27025       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_login) > run RPORT=27026 USERNAME=admin PASSWORD=adminpassword
[*] 127.0.0.1:27026       - Scanning IP: 127.0.0.1
[*] 127.0.0.1:27026       - Negotiated wire protocol: OP_MSG
[*] 127.0.0.1:27026       - Mongo server (version 6.0.28) requires authentication
[*] 127.0.0.1:27026       - Trying user: admin, password: adminpassword
[+] 127.0.0.1:27026       - 127.0.0.1 - SUCCESSFUL LOGIN 'admin' : 'adminpassword' (SCRAM-SHA-1)
[*] 127.0.0.1:27026       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_login) > run RPORT=27027 USERNAME=admin PASSWORD=adminpassword
[*] 127.0.0.1:27027       - Scanning IP: 127.0.0.1
[*] 127.0.0.1:27027       - Negotiated wire protocol: OP_MSG
[*] 127.0.0.1:27027       - Mongo server (version 7.0.43) requires authentication
[*] 127.0.0.1:27027       - Trying user: admin, password: adminpassword
[+] 127.0.0.1:27027       - 127.0.0.1 - SUCCESSFUL LOGIN 'admin' : 'adminpassword' (SCRAM-SHA-1)
[*] 127.0.0.1:27027       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_login) > run RPORT=27028 USERNAME=admin PASSWORD=adminpassword
[*] 127.0.0.1:27028       - Scanning IP: 127.0.0.1
[*] 127.0.0.1:27028       - Negotiated wire protocol: OP_MSG
[*] 127.0.0.1:27028       - buildInfo requires authentication; retrying with configured credentials
[*] 127.0.0.1:27028       - Mongo server (version 8.3.11) requires authentication
[*] 127.0.0.1:27028       - Trying user: admin, password: adminpassword
[+] 127.0.0.1:27028       - 127.0.0.1 - SUCCESSFUL LOGIN 'admin' : 'adminpassword' (SCRAM-SHA-1)
[*] 127.0.0.1:27028       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
