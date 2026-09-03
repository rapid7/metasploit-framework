## Vulnerable Application

This module attempts to brute force authentication credentials for MongoDB.
It supports both SCRAM-SHA-1 (MongoDB 3.0+) and falls back to legacy
MONGODB-CR authentication if SCRAM is unsupported by the target server.

Successfully tested against MongoDB 3.6 with and without authentication

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

#### docker-compose.yml with authentication

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
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: adminpassword
    volumes:
      - mongo_data:/data/db
      - ./init-mongo.js:/docker-entrypoint-initdb.d/init-mongo.js:ro

volumes:
  mongo_data:
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

### MongoDB 3.6 with Authentication

```
msf > use auxiliary/scanner/mongodb/mongodb_login 
msf auxiliary(scanner/mongodb/mongodb_login) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf auxiliary(scanner/mongodb/mongodb_login) > set username testuser
username => testuser
msf auxiliary(scanner/mongodb/mongodb_login) > set password testpass
password => testpass
msf auxiliary(scanner/mongodb/mongodb_login) > set auth_db intranet
db => intranet
msf auxiliary(scanner/mongodb/mongodb_login) > set verbose true
verbose => true
msf auxiliary(scanner/mongodb/mongodb_login) > run
[*] 127.0.0.1:27017       - Scanning IP: 127.0.0.1
[*] 127.0.0.1:27017       - Mongo server (version 3.6.23) requires authentication
[*] 127.0.0.1:27017       - Trying user: testuser, password: testpass
[+] 127.0.0.1:27017       - SUCCESSFUL LOGIN 'testuser' : 'testpass' (SCRAM-SHA-1)
[*] 127.0.0.1:27017       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### MongoDB 3.6 with NO Authentication

```
msf > use auxiliary/scanner/mongodb/mongodb_login
msf auxiliary(scanner/mongodb/mongodb_login) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf auxiliary(scanner/mongodb/mongodb_login) > set verbose true
verbose => true
msf auxiliary(scanner/mongodb/mongodb_login) > run
[*] 127.0.0.1:27017 - Scanning IP: 127.0.0.1
[+] 127.0.0.1:27017 - Mongo server 127.0.0.1 (version 3.6.23) doesn't use authentication
[*] 127.0.0.1:27017 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
