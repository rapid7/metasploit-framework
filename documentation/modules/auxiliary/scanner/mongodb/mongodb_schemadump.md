## Vulnerable Application

This module connects to an unauthenticated or authenticated MongoDB instance,
authenticates using SCRAM-SHA-1 if credentials are provided, enumerates
databases and collections via wire protocol, samples documents, and dumps
the inferred schema structure.

Sccuessfully tested against MongoDB 3.6 with and without authentication

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
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: adminpassword
      MONGO_INITDB_DATABASE: intranet
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

1. Install the application
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

### MongoDB 3.6 with Authentication

```
msf > use auxiliary/scanner/mongodb/mongodb_schemadump 
msf auxiliary(scanner/mongodb/mongodb_schemadump) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf auxiliary(scanner/mongodb/mongodb_schemadump) > set username admin
username => admin
msf auxiliary(scanner/mongodb/mongodb_schemadump) > set password adminpassword
password => adminpassword
msf auxiliary(scanner/mongodb/mongodb_schemadump) > exploit
[*] 127.0.0.1:27017       - Connected to MongoDB wire protocol
[+] 127.0.0.1:27017       - Authenticated successfully as 'admin' on 'admin'
[+] 127.0.0.1:27017       - Found Databases: admin, config, intranet, local
[*] 127.0.0.1:27017       -   DB 'admin' Collections: system.users, system.version
[*] 127.0.0.1:27017       -   DB 'config' Collections: system.sessions
[*] 127.0.0.1:27017       -   DB 'intranet' Collections: users, config
[*] 127.0.0.1:27017       -   DB 'local' Collections: startup_log
[+] 127.0.0.1:27017       - Schema dumped to loot: /home/h00die/.msf4/loot/20260814091146_default_127.0.0.1_mongodb.schema_850455.json
[*] 127.0.0.1:27017       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### MongoDB 3.6 with NO Authentication

```
msf > use auxiliary/scanner/mongodb/mongodb_schemadump
msf auxiliary(scanner/mongodb/mongodb_schemadump) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf auxiliary(scanner/mongodb/mongodb_schemadump) > set verbose true
verbose => true
msf auxiliary(scanner/mongodb/mongodb_schemadump) > exploit
[*] 127.0.0.1:27017       - Connected to MongoDB wire protocol
[+] 127.0.0.1:27017       - Authenticated successfully as 'admin' on 'admin'
[*] 127.0.0.1:27017       - Post-auth listDatabases reply: {"databases"=>[{"name"=>"admin", "sizeOnDisk"=>81920.0, "empty"=>false}, {"name"=>"config", "sizeOnDisk"=>12288.0, "empty"=>false}, {"name"=>"intranet", "sizeOnDisk"=>65536.0, "empty"=>false}, {"name"=>"local", "sizeOnDisk"=>65536.0, "empty"=>false}], "totalSize"=>225280.0, "ok"=>1.0}
[+] 127.0.0.1:27017       - Found Databases: admin, config, intranet, local
[*] 127.0.0.1:27017       -   DB 'admin' Collections: system.users, system.version
[+] 127.0.0.1:27017       -     Schema for admin.system.users:
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
[+] 127.0.0.1:27017       -     Schema for admin.system.version:
    - _id (String)
    - version (String)
    - currentVersion (Integer)
[*] 127.0.0.1:27017       -   DB 'config' Collections: system.sessions
[*] 127.0.0.1:27017       -     Collection config.system.sessions is empty or returned no fields.
[*] 127.0.0.1:27017       -   DB 'intranet' Collections: users, config
[+] 127.0.0.1:27017       -     Schema for intranet.users:
    - _id (ObjectId)
    - user (String)
    - role (String)
    - email (String)
[+] 127.0.0.1:27017       -     Schema for intranet.config:
    - _id (ObjectId)
    - key (String)
    - value (String)
    - note (String)
[*] 127.0.0.1:27017       -   DB 'local' Collections: startup_log
[+] 127.0.0.1:27017       -     Schema for local.startup_log:
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
[+] 127.0.0.1:27017       - Schema dumped to loot: /home/h00die/.msf4/loot/20260814093115_default_127.0.0.1_mongodb.schema_973313.json
[*] 127.0.0.1:27017       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```