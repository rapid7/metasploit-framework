## Vulnerable Application

etcd is a distributed reliable key-value store.  It exposes and API from which you can obtain the version of etcd and related components.

### Docker

  1. `docker run -p 2379:2379 miguelgrinberg/easy-etcd`

## Verification Steps

  1. Install the application
  2. Start msfconsole
  3. Do: ```use auxiliary/scanner/etcd/version```
  4. Do: ```set rhosts [IPs]```
  5. Do: ```run```
  6. You should get a JSON response for the version and the service identified in `services`.

## Scenarios

### etcd in Docker

```
msf5 > use auxiliary/scanner/etcd/version
msf5 auxiliary(scanner/etcd/version) > set RHOSTS localhost
RHOSTS => localhost
msf5 auxiliary(scanner/etcd/version) > run

[+] 127.0.0.1:2379       : {"etcdserver"=>"3.1.3", "etcdcluster"=>"3.1.0"}
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/etcd/version) > services
Services
========

host       port  proto  name  state  info
----       ----  -----  ----  -----  ----
127.0.0.1  2379  tcp    etcd  open   {"etcdserver"=>"3.1.3", "etcdcluster"=>"3.1.0"}
```
