## Vulnerable Application

This module scans for Apache Solr instances and fingerprints the
running version. It reads the `/admin/info/system` handler (JSON)
beneath the configured TARGETURI (`/solr` by default, Solr's built-in
hostContext) and extracts the solr-spec-version field. When the
handler is protected by basic authentication the module retries with
the configured credentials, which default to the secure-by-default
solr:SolrRocks account introduced in Solr 9.8.0, reporting when they
are accepted. If the handler stays unreadable the module falls back
to the admin UI pages, whose asset URLs leak the running version
even before authentication. The result is recorded as service
evidence for the host.

### Docker Installs

Pick the version you want to run, and run it.

```
docker run -d -p 8983:8983 solr:8.1.1-slim
docker run -d -p 8983:8983 solr:8.2.0-slim
docker run -d -p 8983:8983 solr:8.3.1-slim
docker run -d -p 8983:8983 solr:8.4.1-slim
docker run -d -p 8983:8983 solr:8.5.2-slim
docker run -d -p 8983:8983 solr:8.6.3-slim
docker run -d -p 8983:8983 solr:8.7.0-slim
docker run -d -p 8983:8983 solr:8.8.2-slim
docker run -d -p 8983:8983 solr:8.9.0-slim
docker run -d -p 8983:8983 solr:8.10.1-slim
docker run -d -p 8983:8983 solr:8.11.1-slim
docker run -d -p 8983:8983 solr:8.11.4-slim
docker run -d -p 8983:8983 solr:9.0.0
docker run -d -p 8983:8983 solr:9.1.1
docker run -d -p 8983:8983 solr:9.2.1
docker run -d -p 8983:8983 solr:9.3.0-slim
docker run -d -p 8983:8983 solr:9.4.1-slim
docker run -d -p 8983:8983 solr:9.5.0-slim
docker run -d -p 8983:8983 solr:9.6.1-slim
docker run -d -p 8983:8983 solr:9.7.0-slim
docker run -d -p 8983:8983 solr:9.8.1-slim
docker run -d -p 8983:8983 solr:9.9.0-slim
docker run -d -p 8983:8983 solr:10.0.0-slim
```

## Verification Steps

1. Run the docker image
1. Start msfconsole
1. Do: `use auxiliary/scanner/http/apache_solr_version`
1. Do: `set rhosts [ip]`
1. Do: `run`
1. You should get the version number of the solr instance.

## Options

### TARGETURI

The path to the target instance of the application. (Default: `/solr`)

### USERNAME

Username to use if required, default is the Solr >= 9.8.0 secure-by-default username of `solr`

### PASSWORD

Password to use if required, default is the Solr >= 9.8.0 secure-by-default password of `SolrRocks`

## Scenarios

### Docker image of 9.3.0

```
msf > use auxiliary/scanner/http/apache_solr_version 
msf auxiliary(scanner/http/apache_solr_version) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf auxiliary(scanner/http/apache_solr_version) > run
[+] Apache Solr 9.3.0 (Lucene 9.7.0) found at /solr
[*] No authentication required to read the admin info handler
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Docker image of 8.9.0

```
msf > use auxiliary/scanner/http/apache_solr_version 
msf auxiliary(scanner/http/apache_solr_version) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf auxiliary(scanner/http/apache_solr_version) > run
[+] Apache Solr 8.9.0 found at /solr
[*] No authentication required to read the admin info handler
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Docker image of 10.0.0

```
msf > use auxiliary/scanner/http/apache_solr_version 
msf auxiliary(scanner/http/apache_solr_version) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf auxiliary(scanner/http/apache_solr_version) > run
[+] Apache Solr 10.0.0 (Lucene 10.3.2) found at /solr
[*] No authentication required to read the admin info handler
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
