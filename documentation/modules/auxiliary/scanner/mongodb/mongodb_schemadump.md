## Vulnerable Application

This module connects to an unauthenticated or authenticated MongoDB instance,
authenticates using SCRAM-SHA-1 if credentials are provided, enumerates
databases and collections via wire protocol, samples documents, and dumps
the inferred schema structure.

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
1. Do: `use auxiliary/scanner/mongodb/mongodb_schemadump`
1. Optionally Do: `set username <username>`
1. Optionally Do: `set password <password>`
1. Do: `set rhost [ip]`
1. Do: `run`
1. You should get a schema dump

## Options

### DB_NAME

Specific database to enumerate (leave blank for all). Defaults to ``

### AUTH_DB

Database to authenticate against. Defaults to `admin`

### USERNAME

Username for authentication. Defaults to ``

### PASSWORD

Password for authentication. Defaults to ``

### SAMPLE_SIZE

Number of sample documents to inspect per collection for schema mapping. Defaults to `5`

## Scenarios

### MongoDB 3.6.23, 4.4.30, 5.0.33, 6.0.28, 7.0.43, 8.3.11 with and without Authentication

```
msf > use auxiliary/scanner/mongodb/mongodb_schemadump
msf auxiliary(scanner/mongodb/mongodb_schemadump) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf auxiliary(scanner/mongodb/mongodb_schemadump) > run RPORT=27017
[*] 127.0.0.1:27017       - Connected to MongoDB wire protocol
[*] 127.0.0.1:27017       - Negotiated wire protocol: OP_MSG
[*] 127.0.0.1:27017       - Post-auth listDatabases reply: {"databases"=>[{"name"=>"admin", "sizeOnDisk"=>32768.0, "empty"=>false}, {"name"=>"config", "sizeOnDisk"=>12288.0, "empty"=>false}, {"name"=>"local", "sizeOnDisk"=>32768.0, "empty"=>false}], "totalSize"=>77824.0, "ok"=>1.0}
[+] 127.0.0.1:27017       - Found Databases: admin, config, local
[*] 127.0.0.1:27017       -   DB 'admin' Collections: system.version
[+] 127.0.0.1:27017       -     Schema for admin.system.version:
    - _id (String)
    - version (String)
[*] 127.0.0.1:27017       -   DB 'config' Collections: system.sessions
[*] 127.0.0.1:27017       -     Collection config.system.sessions is empty or returned no fields.
[*] 127.0.0.1:27017       -   DB 'local' Collections: startup_log
[+] 127.0.0.1:27017       -     Schema for local.startup_log:
    - _id (String)
    - hostname (String)
    - startTime (Time)
    - startTimeLocal (String)
    - cmdLine (Document)
    - cmdLine.net (Document)
    - cmdLine.net.bindIpAll (TrueClass)
    - pid (Integer)
    - buildinfo (Document)
    - buildinfo.version (String)
    - buildinfo.gitVersion (String)
    - buildinfo.modules (Array)
    - buildinfo.allocator (String)
    - buildinfo.javascriptEngine (String)
    - buildinfo.sysInfo (String)
    - buildinfo.versionArray (Array)
    - buildinfo.openssl (Document)
    - buildinfo.openssl.running (String)
    - buildinfo.openssl.compiled (String)
    - buildinfo.buildEnvironment (Document)
    - buildinfo.buildEnvironment.distmod (String)
    - buildinfo.buildEnvironment.distarch (String)
    - buildinfo.buildEnvironment.cc (String)
    - buildinfo.buildEnvironment.ccflags (String)
    - buildinfo.buildEnvironment.cxx (String)
    - buildinfo.buildEnvironment.cxxflags (String)
    - buildinfo.buildEnvironment.linkflags (String)
    - buildinfo.buildEnvironment.target_arch (String)
    - buildinfo.buildEnvironment.target_os (String)
    - buildinfo.bits (Integer)
    - buildinfo.debug (FalseClass)
    - buildinfo.maxBsonObjectSize (Integer)
    - buildinfo.storageEngines (Array)
[+] 127.0.0.1:27017       - Schema dumped to loot: /root/.msf4/loot/20260915080940_default_127.0.0.1_mongodb.schema_582319.json
[*] 127.0.0.1:27017       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_schemadump) > run RPORT=27018
[*] 127.0.0.1:27018       - Connected to MongoDB wire protocol
[*] 127.0.0.1:27018       - Negotiated wire protocol: OP_MSG
[*] 127.0.0.1:27018       - Post-auth listDatabases reply: {"databases"=>[{"name"=>"admin", "sizeOnDisk"=>40960.0, "empty"=>false}, {"name"=>"config", "sizeOnDisk"=>61440.0, "empty"=>false}, {"name"=>"local", "sizeOnDisk"=>40960.0, "empty"=>false}], "totalSize"=>143360.0, "ok"=>1.0}
[+] 127.0.0.1:27018       - Found Databases: admin, config, local
[*] 127.0.0.1:27018       -   DB 'admin' Collections: system.version
[+] 127.0.0.1:27018       -     Schema for admin.system.version:
    - _id (String)
    - version (String)
[*] 127.0.0.1:27018       -   DB 'config' Collections: system.sessions
[*] 127.0.0.1:27018       -     Collection config.system.sessions is empty or returned no fields.
[*] 127.0.0.1:27018       -   DB 'local' Collections: startup_log
[+] 127.0.0.1:27018       -     Schema for local.startup_log:
    - _id (String)
    - hostname (String)
    - startTime (Time)
    - startTimeLocal (String)
    - cmdLine (Document)
    - cmdLine.net (Document)
    - cmdLine.net.bindIp (String)
    - pid (Integer)
    - buildinfo (Document)
    - buildinfo.version (String)
    - buildinfo.gitVersion (String)
    - buildinfo.modules (Array)
    - buildinfo.allocator (String)
    - buildinfo.javascriptEngine (String)
    - buildinfo.sysInfo (String)
    - buildinfo.versionArray (Array)
    - buildinfo.openssl (Document)
    - buildinfo.openssl.running (String)
    - buildinfo.openssl.compiled (String)
    - buildinfo.buildEnvironment (Document)
    - buildinfo.buildEnvironment.distmod (String)
    - buildinfo.buildEnvironment.distarch (String)
    - buildinfo.buildEnvironment.cc (String)
    - buildinfo.buildEnvironment.ccflags (String)
    - buildinfo.buildEnvironment.cxx (String)
    - buildinfo.buildEnvironment.cxxflags (String)
    - buildinfo.buildEnvironment.linkflags (String)
    - buildinfo.buildEnvironment.target_arch (String)
    - buildinfo.buildEnvironment.target_os (String)
    - buildinfo.buildEnvironment.cppdefines (String)
    - buildinfo.bits (Integer)
    - buildinfo.debug (FalseClass)
    - buildinfo.maxBsonObjectSize (Integer)
    - buildinfo.storageEngines (Array)
[+] 127.0.0.1:27018       - Schema dumped to loot: /root/.msf4/loot/20260915080940_default_127.0.0.1_mongodb.schema_977635.json
[*] 127.0.0.1:27018       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_schemadump) > run RPORT=27019
[*] 127.0.0.1:27019       - Connected to MongoDB wire protocol
[*] 127.0.0.1:27019       - Negotiated wire protocol: OP_MSG
[*] 127.0.0.1:27019       - Post-auth listDatabases reply: {"databases"=>[{"name"=>"admin", "sizeOnDisk"=>40960, "empty"=>false}, {"name"=>"config", "sizeOnDisk"=>61440, "empty"=>false}, {"name"=>"local", "sizeOnDisk"=>40960, "empty"=>false}], "totalSize"=>143360, "totalSizeMb"=>0, "ok"=>1.0}
[+] 127.0.0.1:27019       - Found Databases: admin, config, local
[*] 127.0.0.1:27019       -   DB 'admin' Collections: system.version
[+] 127.0.0.1:27019       -     Schema for admin.system.version:
    - _id (String)
    - version (String)
[*] 127.0.0.1:27019       -   DB 'config' Collections: system.sessions
[*] 127.0.0.1:27019       -     Collection config.system.sessions is empty or returned no fields.
[*] 127.0.0.1:27019       -   DB 'local' Collections: startup_log
[+] 127.0.0.1:27019       -     Schema for local.startup_log:
    - _id (String)
    - hostname (String)
    - startTime (Time)
    - startTimeLocal (String)
    - cmdLine (Document)
    - cmdLine.net (Document)
    - cmdLine.net.bindIp (String)
    - pid (Integer)
    - buildinfo (Document)
    - buildinfo.version (String)
    - buildinfo.gitVersion (String)
    - buildinfo.modules (Array)
    - buildinfo.allocator (String)
    - buildinfo.javascriptEngine (String)
    - buildinfo.sysInfo (String)
    - buildinfo.versionArray (Array)
    - buildinfo.openssl (Document)
    - buildinfo.openssl.running (String)
    - buildinfo.openssl.compiled (String)
    - buildinfo.buildEnvironment (Document)
    - buildinfo.buildEnvironment.distmod (String)
    - buildinfo.buildEnvironment.distarch (String)
    - buildinfo.buildEnvironment.cc (String)
    - buildinfo.buildEnvironment.ccflags (String)
    - buildinfo.buildEnvironment.cxx (String)
    - buildinfo.buildEnvironment.cxxflags (String)
    - buildinfo.buildEnvironment.linkflags (String)
    - buildinfo.buildEnvironment.target_arch (String)
    - buildinfo.buildEnvironment.target_os (String)
    - buildinfo.buildEnvironment.cppdefines (String)
    - buildinfo.bits (Integer)
    - buildinfo.debug (FalseClass)
    - buildinfo.maxBsonObjectSize (Integer)
    - buildinfo.storageEngines (Array)
[+] 127.0.0.1:27019       - Schema dumped to loot: /root/.msf4/loot/20260915080940_default_127.0.0.1_mongodb.schema_734410.json
[*] 127.0.0.1:27019       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_schemadump) > run RPORT=27020
[*] 127.0.0.1:27020       - Connected to MongoDB wire protocol
[*] 127.0.0.1:27020       - Negotiated wire protocol: OP_MSG
[*] 127.0.0.1:27020       - Post-auth listDatabases reply: {"databases"=>[{"name"=>"admin", "sizeOnDisk"=>40960, "empty"=>false}, {"name"=>"config", "sizeOnDisk"=>61440, "empty"=>false}, {"name"=>"local", "sizeOnDisk"=>40960, "empty"=>false}], "totalSize"=>143360, "totalSizeMb"=>0, "ok"=>1.0}
[+] 127.0.0.1:27020       - Found Databases: admin, config, local
[*] 127.0.0.1:27020       -   DB 'admin' Collections: system.version
[+] 127.0.0.1:27020       -     Schema for admin.system.version:
    - _id (String)
    - version (String)
[*] 127.0.0.1:27020       -   DB 'config' Collections: system.sessions
[*] 127.0.0.1:27020       -     Collection config.system.sessions is empty or returned no fields.
[*] 127.0.0.1:27020       -   DB 'local' Collections: startup_log
[+] 127.0.0.1:27020       -     Schema for local.startup_log:
    - _id (String)
    - hostname (String)
    - startTime (Time)
    - startTimeLocal (String)
    - cmdLine (Document)
    - cmdLine.net (Document)
    - cmdLine.net.bindIp (String)
    - pid (Integer)
    - buildinfo (Document)
    - buildinfo.version (String)
    - buildinfo.gitVersion (String)
    - buildinfo.modules (Array)
    - buildinfo.allocator (String)
    - buildinfo.javascriptEngine (String)
    - buildinfo.sysInfo (String)
    - buildinfo.versionArray (Array)
    - buildinfo.openssl (Document)
    - buildinfo.openssl.running (String)
    - buildinfo.openssl.compiled (String)
    - buildinfo.buildEnvironment (Document)
    - buildinfo.buildEnvironment.distmod (String)
    - buildinfo.buildEnvironment.distarch (String)
    - buildinfo.buildEnvironment.cc (String)
    - buildinfo.buildEnvironment.ccflags (String)
    - buildinfo.buildEnvironment.cxx (String)
    - buildinfo.buildEnvironment.cxxflags (String)
    - buildinfo.buildEnvironment.linkflags (String)
    - buildinfo.buildEnvironment.target_arch (String)
    - buildinfo.buildEnvironment.target_os (String)
    - buildinfo.buildEnvironment.cppdefines (String)
    - buildinfo.bits (Integer)
    - buildinfo.debug (FalseClass)
    - buildinfo.maxBsonObjectSize (Integer)
    - buildinfo.storageEngines (Array)
[+] 127.0.0.1:27020       - Schema dumped to loot: /root/.msf4/loot/20260915080940_default_127.0.0.1_mongodb.schema_048491.json
[*] 127.0.0.1:27020       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_schemadump) > run RPORT=27021
[*] 127.0.0.1:27021       - Connected to MongoDB wire protocol
[*] 127.0.0.1:27021       - Negotiated wire protocol: OP_MSG
[*] 127.0.0.1:27021       - Post-auth listDatabases reply: {"databases"=>[{"name"=>"admin", "sizeOnDisk"=>40960, "empty"=>false}, {"name"=>"config", "sizeOnDisk"=>73728, "empty"=>false}, {"name"=>"local", "sizeOnDisk"=>40960, "empty"=>false}], "totalSize"=>155648, "totalSizeMb"=>0, "ok"=>1.0}
[+] 127.0.0.1:27021       - Found Databases: admin, config, local
[*] 127.0.0.1:27021       -   DB 'admin' Collections: system.version
[+] 127.0.0.1:27021       -     Schema for admin.system.version:
    - _id (String)
    - version (String)
[*] 127.0.0.1:27021       -   DB 'config' Collections: system.sessions
[*] 127.0.0.1:27021       -     Collection config.system.sessions is empty or returned no fields.
[*] 127.0.0.1:27021       -   DB 'local' Collections: startup_log
[+] 127.0.0.1:27021       -     Schema for local.startup_log:
    - _id (String)
    - hostname (String)
    - startTime (Time)
    - startTimeLocal (String)
    - cmdLine (Document)
    - cmdLine.net (Document)
    - cmdLine.net.bindIp (String)
    - pid (Integer)
    - buildinfo (Document)
    - buildinfo.version (String)
    - buildinfo.gitVersion (String)
    - buildinfo.modules (Array)
    - buildinfo.allocator (String)
    - buildinfo.javascriptEngine (String)
    - buildinfo.sysInfo (String)
    - buildinfo.versionArray (Array)
    - buildinfo.openssl (Document)
    - buildinfo.openssl.running (String)
    - buildinfo.openssl.compiled (String)
    - buildinfo.buildEnvironment (Document)
    - buildinfo.buildEnvironment.distmod (String)
    - buildinfo.buildEnvironment.distarch (String)
    - buildinfo.buildEnvironment.cc (String)
    - buildinfo.buildEnvironment.ccflags (String)
    - buildinfo.buildEnvironment.cxx (String)
    - buildinfo.buildEnvironment.cxxflags (String)
    - buildinfo.buildEnvironment.linkflags (String)
    - buildinfo.buildEnvironment.target_arch (String)
    - buildinfo.buildEnvironment.target_os (String)
    - buildinfo.buildEnvironment.cppdefines (String)
    - buildinfo.bits (Integer)
    - buildinfo.debug (FalseClass)
    - buildinfo.maxBsonObjectSize (Integer)
    - buildinfo.storageEngines (Array)
[+] 127.0.0.1:27021       - Schema dumped to loot: /root/.msf4/loot/20260915080941_default_127.0.0.1_mongodb.schema_986813.json
[*] 127.0.0.1:27021       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_schemadump) > run RPORT=27022
[*] 127.0.0.1:27022       - Connected to MongoDB wire protocol
[*] 127.0.0.1:27022       - Negotiated wire protocol: OP_MSG
[*] 127.0.0.1:27022       - Post-auth listDatabases reply: {"databases"=>[{"name"=>"admin", "sizeOnDisk"=>40960, "empty"=>false}, {"name"=>"config", "sizeOnDisk"=>49152, "empty"=>false}, {"name"=>"local", "sizeOnDisk"=>40960, "empty"=>false}], "totalSize"=>131072, "totalSizeMb"=>0, "ok"=>1.0}
[+] 127.0.0.1:27022       - Found Databases: admin, config, local
[*] 127.0.0.1:27022       -   DB 'admin' Collections: system.version
[+] 127.0.0.1:27022       -     Schema for admin.system.version:
    - _id (String)
    - version (String)
[*] 127.0.0.1:27022       -   DB 'config' Collections: system.sessions
[*] 127.0.0.1:27022       -     Collection config.system.sessions is empty or returned no fields.
[*] 127.0.0.1:27022       -   DB 'local' Collections: startup_log
[+] 127.0.0.1:27022       -     Schema for local.startup_log:
    - _id (String)
    - hostname (String)
    - startTime (Time)
    - startTimeLocal (String)
    - cmdLine (Document)
    - cmdLine.net (Document)
    - cmdLine.net.bindIp (String)
    - pid (Integer)
    - buildinfo (Document)
    - buildinfo.version (String)
    - buildinfo.versionArray (Array)
    - buildinfo.gitVersion (String)
    - buildinfo.modules (Array)
    - buildinfo.allocator (String)
    - buildinfo.javascriptEngine (String)
    - buildinfo.sysinfo (String)
    - buildinfo.openssl (Document)
    - buildinfo.openssl.running (String)
    - buildinfo.openssl.compiled (String)
    - buildinfo.buildEnvironment (Document)
    - buildinfo.buildEnvironment.distmod (String)
    - buildinfo.buildEnvironment.distarch (String)
    - buildinfo.buildEnvironment.cc (String)
    - buildinfo.buildEnvironment.ccflags (String)
    - buildinfo.buildEnvironment.cxx (String)
    - buildinfo.buildEnvironment.cxxflags (String)
    - buildinfo.buildEnvironment.linkflags (String)
    - buildinfo.buildEnvironment.target_arch (String)
    - buildinfo.buildEnvironment.target_os (String)
    - buildinfo.buildEnvironment.cppdefines (String)
    - buildinfo.bits (Integer)
    - buildinfo.debug (FalseClass)
    - buildinfo.maxBsonObjectSize (Integer)
    - buildinfo.storageEngines (Array)
[+] 127.0.0.1:27022       - Schema dumped to loot: /root/.msf4/loot/20260915080941_default_127.0.0.1_mongodb.schema_100363.json
[*] 127.0.0.1:27022       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_schemadump) > run RPORT=27023 USERNAME=admin PASSWORD=adminpassword
[*] 127.0.0.1:27023       - Connected to MongoDB wire protocol
[*] 127.0.0.1:27023       - Negotiated wire protocol: OP_MSG
[+] 127.0.0.1:27023       - Authenticated as 'admin' on 'admin' via SCRAM-SHA-1
[*] 127.0.0.1:27023       - Post-auth listDatabases reply: {"databases"=>[{"name"=>"admin", "sizeOnDisk"=>81920.0, "empty"=>false}, {"name"=>"config", "sizeOnDisk"=>12288.0, "empty"=>false}, {"name"=>"intranet", "sizeOnDisk"=>65536.0, "empty"=>false}, {"name"=>"local", "sizeOnDisk"=>65536.0, "empty"=>false}], "totalSize"=>225280.0, "ok"=>1.0}
[+] 127.0.0.1:27023       - Found Databases: admin, config, intranet, local
[*] 127.0.0.1:27023       -   DB 'admin' Collections: system.users, system.version
[+] 127.0.0.1:27023       -     Schema for admin.system.users:
    - _id (String)
    - userId (Binary)
    - user (String)
    - db (String)
    - credentials (Document)
    - credentials.SCRAM-SHA-1 (Document)
    - credentials.SCRAM-SHA-1.iterationCount (Integer)
    - credentials.SCRAM-SHA-1.salt (String)
    - credentials.SCRAM-SHA-1.storedKey (String)
    - credentials.SCRAM-SHA-1.serverKey (String)
    - roles (Array)
[+] 127.0.0.1:27023       -     Schema for admin.system.version:
    - _id (String)
    - version (String)
    - currentVersion (Integer)
[*] 127.0.0.1:27023       -   DB 'config' Collections: system.sessions
[-] 127.0.0.1:27023       - Query on config.system.sessions failed: not authorized on config to execute command { find: "system.sessions", filter: {}, batchSize: 5, $db: "config" }
[*] 127.0.0.1:27023       -     Collection config.system.sessions is empty or returned no fields.
[*] 127.0.0.1:27023       -   DB 'intranet' Collections: users, config
[+] 127.0.0.1:27023       -     Schema for intranet.users:
    - _id (ObjectId)
    - user (String)
    - role (String)
    - email (String)
[+] 127.0.0.1:27023       -     Schema for intranet.config:
    - _id (ObjectId)
    - key (String)
    - value (String)
    - note (String)
[*] 127.0.0.1:27023       -   DB 'local' Collections: startup_log
[+] 127.0.0.1:27023       -     Schema for local.startup_log:
    - _id (String)
    - hostname (String)
    - startTime (Time)
    - startTimeLocal (String)
    - cmdLine (Document)
    - cmdLine.net (Document)
    - cmdLine.net.bindIp (String)
    - cmdLine.net.port (Integer)
    - cmdLine.net.ssl (Document)
    - cmdLine.net.ssl.mode (String)
    - cmdLine.processManagement (Document)
    - cmdLine.processManagement.fork (TrueClass)
    - cmdLine.processManagement.pidFilePath (String)
    - cmdLine.systemLog (Document)
    - cmdLine.systemLog.destination (String)
    - cmdLine.systemLog.logAppend (TrueClass)
    - cmdLine.systemLog.path (String)
    - pid (Integer)
    - buildinfo (Document)
    - buildinfo.version (String)
    - buildinfo.gitVersion (String)
    - buildinfo.modules (Array)
    - buildinfo.allocator (String)
    - buildinfo.javascriptEngine (String)
    - buildinfo.sysInfo (String)
    - buildinfo.versionArray (Array)
    - buildinfo.openssl (Document)
    - buildinfo.openssl.running (String)
    - buildinfo.openssl.compiled (String)
    - buildinfo.buildEnvironment (Document)
    - buildinfo.buildEnvironment.distmod (String)
    - buildinfo.buildEnvironment.distarch (String)
    - buildinfo.buildEnvironment.cc (String)
    - buildinfo.buildEnvironment.ccflags (String)
    - buildinfo.buildEnvironment.cxx (String)
    - buildinfo.buildEnvironment.cxxflags (String)
    - buildinfo.buildEnvironment.linkflags (String)
    - buildinfo.buildEnvironment.target_arch (String)
    - buildinfo.buildEnvironment.target_os (String)
    - buildinfo.bits (Integer)
    - buildinfo.debug (FalseClass)
    - buildinfo.maxBsonObjectSize (Integer)
    - buildinfo.storageEngines (Array)
    - cmdLine.net.bindIpAll (TrueClass)
    - cmdLine.security (Document)
    - cmdLine.security.authorization (String)
[+] 127.0.0.1:27023       - Schema dumped to loot: /root/.msf4/loot/20260915080941_default_127.0.0.1_mongodb.schema_453126.json
[*] 127.0.0.1:27023       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_schemadump) > run RPORT=27024 USERNAME=admin PASSWORD=adminpassword
[*] 127.0.0.1:27024       - Connected to MongoDB wire protocol
[*] 127.0.0.1:27024       - Negotiated wire protocol: OP_MSG
[+] 127.0.0.1:27024       - Authenticated as 'admin' on 'admin' via SCRAM-SHA-1
[*] 127.0.0.1:27024       - Post-auth listDatabases reply: {"databases"=>[{"name"=>"admin", "sizeOnDisk"=>102400.0, "empty"=>false}, {"name"=>"config", "sizeOnDisk"=>61440.0, "empty"=>false}, {"name"=>"intranet", "sizeOnDisk"=>81920.0, "empty"=>false}, {"name"=>"local", "sizeOnDisk"=>73728.0, "empty"=>false}], "totalSize"=>319488.0, "ok"=>1.0}
[+] 127.0.0.1:27024       - Found Databases: admin, config, intranet, local
[*] 127.0.0.1:27024       -   DB 'admin' Collections: system.version, system.users
[+] 127.0.0.1:27024       -     Schema for admin.system.version:
    - _id (String)
    - version (String)
    - currentVersion (Integer)
[+] 127.0.0.1:27024       -     Schema for admin.system.users:
    - _id (String)
    - userId (Binary)
    - user (String)
    - db (String)
    - credentials (Document)
    - credentials.SCRAM-SHA-1 (Document)
    - credentials.SCRAM-SHA-1.iterationCount (Integer)
    - credentials.SCRAM-SHA-1.salt (String)
    - credentials.SCRAM-SHA-1.storedKey (String)
    - credentials.SCRAM-SHA-1.serverKey (String)
    - credentials.SCRAM-SHA-256 (Document)
    - credentials.SCRAM-SHA-256.iterationCount (Integer)
    - credentials.SCRAM-SHA-256.salt (String)
    - credentials.SCRAM-SHA-256.storedKey (String)
    - credentials.SCRAM-SHA-256.serverKey (String)
    - roles (Array)
[*] 127.0.0.1:27024       -   DB 'config' Collections: system.sessions
[-] 127.0.0.1:27024       - Query on config.system.sessions failed: not authorized on config to execute command { find: "system.sessions", filter: {}, batchSize: 5, $db: "config" }
[*] 127.0.0.1:27024       -     Collection config.system.sessions is empty or returned no fields.
[*] 127.0.0.1:27024       -   DB 'intranet' Collections: users, config
[+] 127.0.0.1:27024       -     Schema for intranet.users:
    - _id (ObjectId)
    - user (String)
    - role (String)
    - email (String)
[+] 127.0.0.1:27024       -     Schema for intranet.config:
    - _id (ObjectId)
    - key (String)
    - value (String)
    - note (String)
[*] 127.0.0.1:27024       -   DB 'local' Collections: startup_log
[+] 127.0.0.1:27024       -     Schema for local.startup_log:
    - _id (String)
    - hostname (String)
    - startTime (Time)
    - startTimeLocal (String)
    - cmdLine (Document)
    - cmdLine.net (Document)
    - cmdLine.net.bindIp (String)
    - cmdLine.net.port (Integer)
    - cmdLine.net.tls (Document)
    - cmdLine.net.tls.mode (String)
    - cmdLine.processManagement (Document)
    - cmdLine.processManagement.fork (TrueClass)
    - cmdLine.processManagement.pidFilePath (String)
    - cmdLine.systemLog (Document)
    - cmdLine.systemLog.destination (String)
    - cmdLine.systemLog.logAppend (TrueClass)
    - cmdLine.systemLog.path (String)
    - pid (Integer)
    - buildinfo (Document)
    - buildinfo.version (String)
    - buildinfo.gitVersion (String)
    - buildinfo.modules (Array)
    - buildinfo.allocator (String)
    - buildinfo.javascriptEngine (String)
    - buildinfo.sysInfo (String)
    - buildinfo.versionArray (Array)
    - buildinfo.openssl (Document)
    - buildinfo.openssl.running (String)
    - buildinfo.openssl.compiled (String)
    - buildinfo.buildEnvironment (Document)
    - buildinfo.buildEnvironment.distmod (String)
    - buildinfo.buildEnvironment.distarch (String)
    - buildinfo.buildEnvironment.cc (String)
    - buildinfo.buildEnvironment.ccflags (String)
    - buildinfo.buildEnvironment.cxx (String)
    - buildinfo.buildEnvironment.cxxflags (String)
    - buildinfo.buildEnvironment.linkflags (String)
    - buildinfo.buildEnvironment.target_arch (String)
    - buildinfo.buildEnvironment.target_os (String)
    - buildinfo.buildEnvironment.cppdefines (String)
    - buildinfo.bits (Integer)
    - buildinfo.debug (FalseClass)
    - buildinfo.maxBsonObjectSize (Integer)
    - buildinfo.storageEngines (Array)
    - cmdLine.security (Document)
    - cmdLine.security.authorization (String)
[+] 127.0.0.1:27024       - Schema dumped to loot: /root/.msf4/loot/20260915080941_default_127.0.0.1_mongodb.schema_919027.json
[*] 127.0.0.1:27024       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_schemadump) > run RPORT=27025 USERNAME=admin PASSWORD=adminpassword
[*] 127.0.0.1:27025       - Connected to MongoDB wire protocol
[*] 127.0.0.1:27025       - Negotiated wire protocol: OP_MSG
[+] 127.0.0.1:27025       - Authenticated as 'admin' on 'admin' via SCRAM-SHA-1
[*] 127.0.0.1:27025       - Post-auth listDatabases reply: {"databases"=>[{"name"=>"admin", "sizeOnDisk"=>102400, "empty"=>false}, {"name"=>"config", "sizeOnDisk"=>61440, "empty"=>false}, {"name"=>"intranet", "sizeOnDisk"=>81920, "empty"=>false}, {"name"=>"local", "sizeOnDisk"=>73728, "empty"=>false}], "totalSize"=>319488, "totalSizeMb"=>0, "ok"=>1.0}
[+] 127.0.0.1:27025       - Found Databases: admin, config, intranet, local
[*] 127.0.0.1:27025       -   DB 'admin' Collections: system.users, system.version
[+] 127.0.0.1:27025       -     Schema for admin.system.users:
    - _id (String)
    - userId (Binary)
    - user (String)
    - db (String)
    - credentials (Document)
    - credentials.SCRAM-SHA-1 (Document)
    - credentials.SCRAM-SHA-1.iterationCount (Integer)
    - credentials.SCRAM-SHA-1.salt (String)
    - credentials.SCRAM-SHA-1.storedKey (String)
    - credentials.SCRAM-SHA-1.serverKey (String)
    - credentials.SCRAM-SHA-256 (Document)
    - credentials.SCRAM-SHA-256.iterationCount (Integer)
    - credentials.SCRAM-SHA-256.salt (String)
    - credentials.SCRAM-SHA-256.storedKey (String)
    - credentials.SCRAM-SHA-256.serverKey (String)
    - roles (Array)
[+] 127.0.0.1:27025       -     Schema for admin.system.version:
    - _id (String)
    - version (String)
    - currentVersion (Integer)
[*] 127.0.0.1:27025       -   DB 'config' Collections: system.sessions
[-] 127.0.0.1:27025       - Query on config.system.sessions failed: not authorized on config to execute command { find: "system.sessions", filter: {}, batchSize: 5, $db: "config" }
[*] 127.0.0.1:27025       -     Collection config.system.sessions is empty or returned no fields.
[*] 127.0.0.1:27025       -   DB 'intranet' Collections: users, config
[+] 127.0.0.1:27025       -     Schema for intranet.users:
    - _id (ObjectId)
    - user (String)
    - role (String)
    - email (String)
[+] 127.0.0.1:27025       -     Schema for intranet.config:
    - _id (ObjectId)
    - key (String)
    - value (String)
    - note (String)
[*] 127.0.0.1:27025       -   DB 'local' Collections: startup_log
[+] 127.0.0.1:27025       -     Schema for local.startup_log:
    - _id (String)
    - hostname (String)
    - startTime (Time)
    - startTimeLocal (String)
    - cmdLine (Document)
    - cmdLine.net (Document)
    - cmdLine.net.bindIp (String)
    - cmdLine.net.port (Integer)
    - cmdLine.net.tls (Document)
    - cmdLine.net.tls.mode (String)
    - cmdLine.processManagement (Document)
    - cmdLine.processManagement.fork (TrueClass)
    - cmdLine.processManagement.pidFilePath (String)
    - cmdLine.systemLog (Document)
    - cmdLine.systemLog.destination (String)
    - cmdLine.systemLog.logAppend (TrueClass)
    - cmdLine.systemLog.path (String)
    - pid (Integer)
    - buildinfo (Document)
    - buildinfo.version (String)
    - buildinfo.gitVersion (String)
    - buildinfo.modules (Array)
    - buildinfo.allocator (String)
    - buildinfo.javascriptEngine (String)
    - buildinfo.sysInfo (String)
    - buildinfo.versionArray (Array)
    - buildinfo.openssl (Document)
    - buildinfo.openssl.running (String)
    - buildinfo.openssl.compiled (String)
    - buildinfo.buildEnvironment (Document)
    - buildinfo.buildEnvironment.distmod (String)
    - buildinfo.buildEnvironment.distarch (String)
    - buildinfo.buildEnvironment.cc (String)
    - buildinfo.buildEnvironment.ccflags (String)
    - buildinfo.buildEnvironment.cxx (String)
    - buildinfo.buildEnvironment.cxxflags (String)
    - buildinfo.buildEnvironment.linkflags (String)
    - buildinfo.buildEnvironment.target_arch (String)
    - buildinfo.buildEnvironment.target_os (String)
    - buildinfo.buildEnvironment.cppdefines (String)
    - buildinfo.bits (Integer)
    - buildinfo.debug (FalseClass)
    - buildinfo.maxBsonObjectSize (Integer)
    - buildinfo.storageEngines (Array)
    - cmdLine.security (Document)
    - cmdLine.security.authorization (String)
[+] 127.0.0.1:27025       - Schema dumped to loot: /root/.msf4/loot/20260915080941_default_127.0.0.1_mongodb.schema_660088.json
[*] 127.0.0.1:27025       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_schemadump) > run RPORT=27026 USERNAME=admin PASSWORD=adminpassword
[*] 127.0.0.1:27026       - Connected to MongoDB wire protocol
[*] 127.0.0.1:27026       - Negotiated wire protocol: OP_MSG
[+] 127.0.0.1:27026       - Authenticated as 'admin' on 'admin' via SCRAM-SHA-1
[*] 127.0.0.1:27026       - Post-auth listDatabases reply: {"databases"=>[{"name"=>"admin", "sizeOnDisk"=>102400, "empty"=>false}, {"name"=>"config", "sizeOnDisk"=>61440, "empty"=>false}, {"name"=>"intranet", "sizeOnDisk"=>81920, "empty"=>false}, {"name"=>"local", "sizeOnDisk"=>73728, "empty"=>false}], "totalSize"=>319488, "totalSizeMb"=>0, "ok"=>1.0}
[+] 127.0.0.1:27026       - Found Databases: admin, config, intranet, local
[*] 127.0.0.1:27026       -   DB 'admin' Collections: system.users, system.version
[+] 127.0.0.1:27026       -     Schema for admin.system.users:
    - _id (String)
    - userId (Binary)
    - user (String)
    - db (String)
    - credentials (Document)
    - credentials.SCRAM-SHA-1 (Document)
    - credentials.SCRAM-SHA-1.iterationCount (Integer)
    - credentials.SCRAM-SHA-1.salt (String)
    - credentials.SCRAM-SHA-1.storedKey (String)
    - credentials.SCRAM-SHA-1.serverKey (String)
    - credentials.SCRAM-SHA-256 (Document)
    - credentials.SCRAM-SHA-256.iterationCount (Integer)
    - credentials.SCRAM-SHA-256.salt (String)
    - credentials.SCRAM-SHA-256.storedKey (String)
    - credentials.SCRAM-SHA-256.serverKey (String)
    - roles (Array)
[+] 127.0.0.1:27026       -     Schema for admin.system.version:
    - _id (String)
    - version (String)
    - currentVersion (Integer)
[*] 127.0.0.1:27026       -   DB 'config' Collections: system.sessions
[-] 127.0.0.1:27026       - Query on config.system.sessions failed: not authorized on config to execute command { find: "system.sessions", filter: {}, batchSize: 5, $db: "config" }
[*] 127.0.0.1:27026       -     Collection config.system.sessions is empty or returned no fields.
[*] 127.0.0.1:27026       -   DB 'intranet' Collections: config, users
[+] 127.0.0.1:27026       -     Schema for intranet.config:
    - _id (ObjectId)
    - key (String)
    - value (String)
    - note (String)
[+] 127.0.0.1:27026       -     Schema for intranet.users:
    - _id (ObjectId)
    - user (String)
    - role (String)
    - email (String)
[*] 127.0.0.1:27026       -   DB 'local' Collections: startup_log
[+] 127.0.0.1:27026       -     Schema for local.startup_log:
    - _id (String)
    - hostname (String)
    - startTime (Time)
    - startTimeLocal (String)
    - cmdLine (Document)
    - cmdLine.net (Document)
    - cmdLine.net.bindIp (String)
    - cmdLine.net.port (Integer)
    - cmdLine.net.tls (Document)
    - cmdLine.net.tls.mode (String)
    - cmdLine.processManagement (Document)
    - cmdLine.processManagement.fork (TrueClass)
    - cmdLine.processManagement.pidFilePath (String)
    - cmdLine.systemLog (Document)
    - cmdLine.systemLog.destination (String)
    - cmdLine.systemLog.logAppend (TrueClass)
    - cmdLine.systemLog.path (String)
    - pid (Integer)
    - buildinfo (Document)
    - buildinfo.version (String)
    - buildinfo.gitVersion (String)
    - buildinfo.modules (Array)
    - buildinfo.allocator (String)
    - buildinfo.javascriptEngine (String)
    - buildinfo.sysInfo (String)
    - buildinfo.versionArray (Array)
    - buildinfo.openssl (Document)
    - buildinfo.openssl.running (String)
    - buildinfo.openssl.compiled (String)
    - buildinfo.buildEnvironment (Document)
    - buildinfo.buildEnvironment.distmod (String)
    - buildinfo.buildEnvironment.distarch (String)
    - buildinfo.buildEnvironment.cc (String)
    - buildinfo.buildEnvironment.ccflags (String)
    - buildinfo.buildEnvironment.cxx (String)
    - buildinfo.buildEnvironment.cxxflags (String)
    - buildinfo.buildEnvironment.linkflags (String)
    - buildinfo.buildEnvironment.target_arch (String)
    - buildinfo.buildEnvironment.target_os (String)
    - buildinfo.buildEnvironment.cppdefines (String)
    - buildinfo.bits (Integer)
    - buildinfo.debug (FalseClass)
    - buildinfo.maxBsonObjectSize (Integer)
    - buildinfo.storageEngines (Array)
    - cmdLine.security (Document)
    - cmdLine.security.authorization (String)
[+] 127.0.0.1:27026       - Schema dumped to loot: /root/.msf4/loot/20260915080942_default_127.0.0.1_mongodb.schema_008292.json
[*] 127.0.0.1:27026       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_schemadump) > run RPORT=27027 USERNAME=admin PASSWORD=adminpassword
[*] 127.0.0.1:27027       - Connected to MongoDB wire protocol
[*] 127.0.0.1:27027       - Negotiated wire protocol: OP_MSG
[+] 127.0.0.1:27027       - Authenticated as 'admin' on 'admin' via SCRAM-SHA-1
[*] 127.0.0.1:27027       - Post-auth listDatabases reply: {"databases"=>[{"name"=>"admin", "sizeOnDisk"=>102400, "empty"=>false}, {"name"=>"config", "sizeOnDisk"=>73728, "empty"=>false}, {"name"=>"intranet", "sizeOnDisk"=>81920, "empty"=>false}, {"name"=>"local", "sizeOnDisk"=>73728, "empty"=>false}], "totalSize"=>331776, "totalSizeMb"=>0, "ok"=>1.0}
[+] 127.0.0.1:27027       - Found Databases: admin, config, intranet, local
[*] 127.0.0.1:27027       -   DB 'admin' Collections: system.users, system.version
[+] 127.0.0.1:27027       -     Schema for admin.system.users:
    - _id (String)
    - userId (Binary)
    - user (String)
    - db (String)
    - credentials (Document)
    - credentials.SCRAM-SHA-1 (Document)
    - credentials.SCRAM-SHA-1.iterationCount (Integer)
    - credentials.SCRAM-SHA-1.salt (String)
    - credentials.SCRAM-SHA-1.storedKey (String)
    - credentials.SCRAM-SHA-1.serverKey (String)
    - credentials.SCRAM-SHA-256 (Document)
    - credentials.SCRAM-SHA-256.iterationCount (Integer)
    - credentials.SCRAM-SHA-256.salt (String)
    - credentials.SCRAM-SHA-256.storedKey (String)
    - credentials.SCRAM-SHA-256.serverKey (String)
    - roles (Array)
[+] 127.0.0.1:27027       -     Schema for admin.system.version:
    - _id (String)
    - version (String)
    - currentVersion (Integer)
[*] 127.0.0.1:27027       -   DB 'config' Collections: system.sessions
[-] 127.0.0.1:27027       - Query on config.system.sessions failed: not authorized on config to execute command { find: "system.sessions", filter: {}, batchSize: 5, $db: "config" }
[*] 127.0.0.1:27027       -     Collection config.system.sessions is empty or returned no fields.
[*] 127.0.0.1:27027       -   DB 'intranet' Collections: config, users
[+] 127.0.0.1:27027       -     Schema for intranet.config:
    - _id (ObjectId)
    - key (String)
    - value (String)
    - note (String)
[+] 127.0.0.1:27027       -     Schema for intranet.users:
    - _id (ObjectId)
    - user (String)
    - role (String)
    - email (String)
[*] 127.0.0.1:27027       -   DB 'local' Collections: startup_log
[+] 127.0.0.1:27027       -     Schema for local.startup_log:
    - _id (String)
    - hostname (String)
    - startTime (Time)
    - startTimeLocal (String)
    - cmdLine (Document)
    - cmdLine.net (Document)
    - cmdLine.net.bindIp (String)
    - cmdLine.net.port (Integer)
    - cmdLine.net.tls (Document)
    - cmdLine.net.tls.mode (String)
    - cmdLine.processManagement (Document)
    - cmdLine.processManagement.fork (TrueClass)
    - cmdLine.processManagement.pidFilePath (String)
    - cmdLine.systemLog (Document)
    - cmdLine.systemLog.destination (String)
    - cmdLine.systemLog.logAppend (TrueClass)
    - cmdLine.systemLog.path (String)
    - pid (Integer)
    - buildinfo (Document)
    - buildinfo.version (String)
    - buildinfo.gitVersion (String)
    - buildinfo.modules (Array)
    - buildinfo.allocator (String)
    - buildinfo.javascriptEngine (String)
    - buildinfo.sysInfo (String)
    - buildinfo.versionArray (Array)
    - buildinfo.openssl (Document)
    - buildinfo.openssl.running (String)
    - buildinfo.openssl.compiled (String)
    - buildinfo.buildEnvironment (Document)
    - buildinfo.buildEnvironment.distmod (String)
    - buildinfo.buildEnvironment.distarch (String)
    - buildinfo.buildEnvironment.cc (String)
    - buildinfo.buildEnvironment.ccflags (String)
    - buildinfo.buildEnvironment.cxx (String)
    - buildinfo.buildEnvironment.cxxflags (String)
    - buildinfo.buildEnvironment.linkflags (String)
    - buildinfo.buildEnvironment.target_arch (String)
    - buildinfo.buildEnvironment.target_os (String)
    - buildinfo.buildEnvironment.cppdefines (String)
    - buildinfo.bits (Integer)
    - buildinfo.debug (FalseClass)
    - buildinfo.maxBsonObjectSize (Integer)
    - buildinfo.storageEngines (Array)
    - cmdLine.security (Document)
    - cmdLine.security.authorization (String)
[+] 127.0.0.1:27027       - Schema dumped to loot: /root/.msf4/loot/20260915080942_default_127.0.0.1_mongodb.schema_959709.json
[*] 127.0.0.1:27027       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/mongodb/mongodb_schemadump) > run RPORT=27028 USERNAME=admin PASSWORD=adminpassword
[*] 127.0.0.1:27028       - Connected to MongoDB wire protocol
[*] 127.0.0.1:27028       - Negotiated wire protocol: OP_MSG
[+] 127.0.0.1:27028       - Authenticated as 'admin' on 'admin' via SCRAM-SHA-1
[*] 127.0.0.1:27028       - Post-auth listDatabases reply: {"databases"=>[{"name"=>"admin", "sizeOnDisk"=>102400, "empty"=>false}, {"name"=>"config", "sizeOnDisk"=>49152, "empty"=>false}, {"name"=>"intranet", "sizeOnDisk"=>81920, "empty"=>false}, {"name"=>"local", "sizeOnDisk"=>73728, "empty"=>false}], "totalSize"=>307200, "totalSizeMb"=>0, "ok"=>1.0}
[+] 127.0.0.1:27028       - Found Databases: admin, config, intranet, local
[*] 127.0.0.1:27028       -   DB 'admin' Collections: system.users, system.version
[+] 127.0.0.1:27028       -     Schema for admin.system.users:
    - _id (String)
    - userId (Binary)
    - user (String)
    - db (String)
    - credentials (Document)
    - credentials.SCRAM-SHA-1 (Document)
    - credentials.SCRAM-SHA-1.iterationCount (Integer)
    - credentials.SCRAM-SHA-1.salt (String)
    - credentials.SCRAM-SHA-1.storedKey (String)
    - credentials.SCRAM-SHA-1.serverKey (String)
    - credentials.SCRAM-SHA-256 (Document)
    - credentials.SCRAM-SHA-256.iterationCount (Integer)
    - credentials.SCRAM-SHA-256.salt (String)
    - credentials.SCRAM-SHA-256.storedKey (String)
    - credentials.SCRAM-SHA-256.serverKey (String)
    - roles (Array)
[+] 127.0.0.1:27028       -     Schema for admin.system.version:
    - _id (String)
    - version (String)
[*] 127.0.0.1:27028       -   DB 'config' Collections: system.sessions
[-] 127.0.0.1:27028       - Query on config.system.sessions failed: not authorized on config to execute command { find: "system.sessions", filter: {}, batchSize: 5, $db: "config" }
[*] 127.0.0.1:27028       -     Collection config.system.sessions is empty or returned no fields.
[*] 127.0.0.1:27028       -   DB 'intranet' Collections: users, config
[+] 127.0.0.1:27028       -     Schema for intranet.users:
    - _id (ObjectId)
    - user (String)
    - role (String)
    - email (String)
[+] 127.0.0.1:27028       -     Schema for intranet.config:
    - _id (ObjectId)
    - key (String)
    - value (String)
    - note (String)
[*] 127.0.0.1:27028       -   DB 'local' Collections: startup_log
[+] 127.0.0.1:27028       -     Schema for local.startup_log:
    - _id (String)
    - hostname (String)
    - startTime (Time)
    - startTimeLocal (String)
    - cmdLine (Document)
    - cmdLine.net (Document)
    - cmdLine.net.bindIp (String)
    - cmdLine.net.port (Integer)
    - cmdLine.net.tls (Document)
    - cmdLine.net.tls.mode (String)
    - cmdLine.processManagement (Document)
    - cmdLine.processManagement.fork (TrueClass)
    - cmdLine.processManagement.pidFilePath (String)
    - cmdLine.systemLog (Document)
    - cmdLine.systemLog.destination (String)
    - cmdLine.systemLog.logAppend (TrueClass)
    - cmdLine.systemLog.path (String)
    - pid (Integer)
    - buildinfo (Document)
    - buildinfo.version (String)
    - buildinfo.versionArray (Array)
    - buildinfo.gitVersion (String)
    - buildinfo.modules (Array)
    - buildinfo.allocator (String)
    - buildinfo.javascriptEngine (String)
    - buildinfo.sysinfo (String)
    - buildinfo.openssl (Document)
    - buildinfo.openssl.running (String)
    - buildinfo.openssl.compiled (String)
    - buildinfo.buildEnvironment (Document)
    - buildinfo.buildEnvironment.distmod (String)
    - buildinfo.buildEnvironment.distarch (String)
    - buildinfo.buildEnvironment.cc (String)
    - buildinfo.buildEnvironment.ccflags (String)
    - buildinfo.buildEnvironment.cxx (String)
    - buildinfo.buildEnvironment.cxxflags (String)
    - buildinfo.buildEnvironment.linkflags (String)
    - buildinfo.buildEnvironment.target_arch (String)
    - buildinfo.buildEnvironment.target_os (String)
    - buildinfo.buildEnvironment.cppdefines (String)
    - buildinfo.bits (Integer)
    - buildinfo.debug (FalseClass)
    - buildinfo.maxBsonObjectSize (Integer)
    - buildinfo.storageEngines (Array)
    - cmdLine.security (Document)
    - cmdLine.security.authorization (String)
[+] 127.0.0.1:27028       - Schema dumped to loot: /root/.msf4/loot/20260915081111_default_127.0.0.1_mongodb.schema_980382.json
[*] 127.0.0.1:27028       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
