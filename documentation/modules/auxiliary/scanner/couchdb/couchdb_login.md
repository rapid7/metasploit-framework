## Vulnerable Application

Apache CouchDB is a nosql database server which communicates over HTTP.  This module will enumerate the server and databases hosted on it.

The following was done on Ubuntu 16.04, and is largely base on [1and1.com](https://www.1and1.com/cloud-community/learn/database/couchdb/install-and-use-couchdb-on-ubuntu-1604/):
  
  1. `sudo apt install software-properties-common`
  2. `sudo add-apt-repository ppa:couchdb/stable`
  3. `sudo apt update`
  4. `sudo apt install couchdb`
  5. Reconfigure couchdb to listen to all interfaces. Edit `/etc/couchdb/local.ini`. Under `[httpd]` add the following line: `bind_address = 0.0.0.0`
  6. Restart the service: `sudo service couchdb restart`
  7. Create an admin user `curl -X PUT http://127.0.0.1:5984/_config/admins/anna -d '"secret"'`

## Verification Steps

  1. Install and configure couchdb
  2. Start msfconsole
  3. Do: `auxiliary/scanner/couchdb/couchdb_login`
  4. Do: `run`

## Scenarios

  A run against the configuration from these docs

  ```
  msf5 > use auxiliary/scanner/couchdb/couchdb_login 
  msf5 auxiliary(scanner/couchdb/couchdb_login) > set rhosts 1.1.1.1
  rhosts => 1.1.1.1
  msf5 auxiliary(scanner/couchdb/couchdb_login) > set username anna
  username => anna
  msf5 auxiliary(scanner/couchdb/couchdb_login) > set password secret
  password => secret
  msf5 auxiliary(scanner/couchdb/couchdb_login) > run
  
  [*] 1.1.1.1:5984 - [001/305] - Trying username:'connect' with password:'connect'
  [*] 1.1.1.1:5984 - [002/305] - Trying username:'sitecom' with password:'sitecom'
  [*] 1.1.1.1:5984 - [003/305] - Trying username:'admin' with password:'1234'
  [*] 1.1.1.1:5984 - [004/305] - Trying username:'cisco' with password:'cisco'
  [*] 1.1.1.1:5984 - [005/305] - Trying username:'cisco' with password:'sanfran'
  [*] 1.1.1.1:5984 - [006/305] - Trying username:'private' with password:'private'
  [*] 1.1.1.1:5984 - [007/305] - Trying username:'wampp' with password:'xampp'
  [*] 1.1.1.1:5984 - [008/305] - Trying username:'newuser' with password:'wampp'
  [*] 1.1.1.1:5984 - [009/305] - Trying username:'xampp-dav-unsecure' with password:'ppmax2011'
  [*] 1.1.1.1:5984 - [010/305] - Trying username:'admin' with password:'turnkey'
  [*] 1.1.1.1:5984 - [011/305] - Trying username:'vagrant' with password:'vagrant'
  [*] 1.1.1.1:5984 - [012/305] - Trying username:'anna' with password:'secret'
  [+] 1.1.1.1:5984 - Successful login with. 'anna' : 'secret'
  [*] 1.1.1.1:5984 - [013/305] - Trying username:'admin' with password:'secret'
  ...snip...
  ```
