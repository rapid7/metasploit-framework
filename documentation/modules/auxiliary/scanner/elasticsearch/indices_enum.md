## Description
This module identifies a list of indices which an Elasticsearch NoSQL database has. This occurs over the REST API, which on community versions is an unauthenticated API. Customers who subscribe to a support plan can add authentication to this API restricting access.

## Vulnerable Application
### Install Elasticsearch on Kali Linux:
With this install, we'll install the free community edition of Elasticsearch, which does not require authentication to the API. However, this is unrealistic in a production environment which will often leverage a support contract to gain authentication, a reverse proxy to add basic authentication, and/or a host firewall to restrict access to this API.

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
1. `use auxiliary/scanner/elasticsearch/indices_enum`
2. `set RHOSTS [ips]`
3. `set RPORT [port]`
4. `run`


## Scenarios
### Elasticsearch 6.3.2 on Kali Linux
```
msf > use auxiliary/scanner/elasticsearch/indices_enum
msf auxiliary(scanner/elasticsearch/indices_enum) > set RHOSTS 10.10.10.25
RHOSTS => 10.10.10.25
msf auxiliary(scanner/elasticsearch/indices_enum) > run

[+] ElasticSearch Indices found: msf_test
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

## Confirming
### [elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/_list_all_indices.html)
 ```
# curl 'http://10.10.10.25:9200/_cat/indices?v'
health status index    uuid                   pri rep docs.count docs.deleted store.size pri.store.size
yellow open   msf_test W83_cAS1QlmePnczS9sLrA   5   1          0            0      1.2kb          1.2kb
```
