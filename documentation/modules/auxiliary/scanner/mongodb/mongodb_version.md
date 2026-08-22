## Vulnerable Application

This module connects to a MongoDB instance and retrieves the server version
using the buildInfo command. No authentication is required for this command.

Tested against MongoDB 3.6.23

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
1. Do: `use auxiliary/scanner/mongodb/mongodb_version`
1. Do: `set rhost [ip]`
1. Do: `run`
1. You should get a version back

## Options

## Scenarios

### MongoDB 3.6 with NO Authentication

```
msf > use auxiliary/scanner/mongodb/mongodb_version 
msf auxiliary(scanner/mongodb/mongodb_version) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf auxiliary(scanner/mongodb/mongodb_version) > run
[*] 127.0.0.1:27017 - Connecting to 127.0.0.1:27017...
[+] 127.0.0.1:27017 - 127.0.0.1:27017 - MongoDB version: 3.6.23
[*] 127.0.0.1:27017 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```