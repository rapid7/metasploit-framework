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

  ```
