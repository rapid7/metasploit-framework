## Vulnerable Application

This module enumerates Elasticsearch instances. It uses the REST API
in order to gather information about the server, the cluster, nodes,
in the cluster, indicies, and pull data from those indicies.

### Docker

Docker install is quite simple, however it won't come with any data making the results rather boring.
However, we can use the the [oliver006/elasticsearch-test-data](https://github.com/oliver006/elasticsearch-test-data)
repo to help auto populate our data.

```
sudo sysctl -w vm.max_map_count=262144
git clone https://github.com/oliver006/elasticsearch-test-data.git
cd elasticsearch-test-data
docker-compose up --detach
docker run --rm -it --network host oliver006/es-test-data  \
    --es_url=http://localhost:9200  \
    --batch_size=10000  \
    --username=elastic \
    --password="esbackup-password"
```


### Install Elasticsearch on Kali Linux
With this install, we'll install the free community edition of Elasticsearch, which does not require authentication to the API. However,
this is unrealistic in a production environment which will often leverage a support contract to gain authentication, a reverse proxy to
add basic authentication, and/or a host firewall to restrict access to this API.

The following instructions assume you are beginning with a fresh Kali installation as the root user.

1. `useradd -M -r elasticsearch`
2. `su elasticsearch`
3. `cd /tmp`
4. `curl -L -O https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-6.3.2.tar.gz`
5. `tar -xvf elasticsearch-6.3.2.tar.gz`
6. `cd elasticsearch-6.3.2/bin`
7. `./elasticsearch`
8. Open a new terminal
9. In the new terminal, `curl -X PUT http://127.0.0.1:9200/msf_test` to create an index for validation purposes

## Verification Steps
1. `use auxiliary/gather/elasticsearch_enum`
2. `set RHOSTS [ips]`
3. `set RPORT [port]`
4. `run`

## Options

## Scenarios
### Elasticsearch 7.9.1 on Docker
```
msf6 > use auxiliary/gather/elasticsearch_enum
msf6 auxiliary(gather/elasticsearch/enum) > set ssl false
[!] Changing the SSL option's value may require changing RPORT!
ssl => false
msf6 auxiliary(gather/elasticsearch/enum) > set password esbackup-password
password => esbackup-password
msf6 auxiliary(gather/elasticsearch/enum) > set username elastic
username => elastic
msf6 auxiliary(gather/elasticsearch/enum) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf6 auxiliary(gather/elasticsearch/enum) > run

[+] Elastic Information
===================

  Name  Cluster Name       Version  Build Type  Lucene Version
  ----  ------------       -------  ----------  --------------
  es01  es-docker-cluster  7.9.1    docker      8.6.2

[+] Node Information
================

  IP          Transport Port  HTTP Port        Version  Name  Uptime  Ram Usage    Node Role  Master  CPU Load  Disk Usage
  --          --------------  ---------        -------  ----  ------  ---------    ---------  ------  --------  ----------
  172.18.0.2  9300            172.18.0.2:9200  7.9.1    es01  1.1h    5.4gb/5.7gb  dilmrt     -       12%       64.8gb/75.6gb
  172.18.0.3  9300            172.18.0.3:9200  7.9.1    es02  1.1h    5.4gb/5.7gb  dilmrt     *       12%       64.8gb/75.6gb

[+] Cluster Information
===================

  Cluster Name       Status  Number of Nodes
  ------------       ------  ---------------
  es-docker-cluster  yellow  2

[+] Indicies Information
====================

  Name       Health  Status  UUID                    Documents  Storage Usage (MB)
  ----       ------  ------  ----                    ---------  ------------------
  test_data  yellow  open    Y2Qms9leTf2riFN89Lik6g  100000     8MB

[+] test_data data stored to /root/.msf4/loot/20230824172328_default_127.0.0.1_elasticserch.ind_635067.csv
[+] User Information
================

  Name                    Roles                                                       Email  Metadata                                                                                         Enabled
  ----                    -----                                                       -----  --------                                                                                         -------
  apm_system              ["apm_system"]                                                     {"_reserved"=>true}                                                                              true
  beats_system            ["beats_system"]                                                   {"_reserved"=>true}                                                                              true
  elastic                 ["superuser"]                                                      {"_reserved"=>true}                                                                              true
  kibana                  ["kibana_system"]                                                  {"_deprecated"=>true, "_deprecated_reason"=>"Please use the [kibana_system] user instead.", "_r  true
                                                                                             eserved"=>true}
  kibana_system           ["kibana_system"]                                                  {"_reserved"=>true}                                                                              true
  logstash_system         ["logstash_system"]                                                {"_reserved"=>true}                                                                              true
  remote_monitoring_user  ["remote_monitoring_collector", "remote_monitoring_agent"]         {"_reserved"=>true}                                                                              true

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
