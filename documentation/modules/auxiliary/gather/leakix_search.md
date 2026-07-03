## Vulnerable Application

This module uses the [LeakIX](https://leakix.net) API to search for exposed services
and data leaks across the internet. LeakIX indexes internet-facing services and leaked
credentials/databases, similar to Shodan or Censys but with a focus on data leaks.

An API key is required. Free keys are available at [https://leakix.net](https://leakix.net).
Pro keys unlock the BULK streaming action and higher page limits.

The module supports six actions:

- **SEARCH** - Query LeakIX with a search string (leak or service scope). Paginated, 20 results per page, max 500 pages.
- **HOST** - Retrieve all known services and leaks for a specific IP address.
- **DOMAIN** - Retrieve all known services and leaks for a specific domain.
- **SUBDOMAINS** - Enumerate known subdomains for a domain.
- **PLUGINS** - List all available LeakIX scanner plugins (useful for building queries).
- **BULK** - Stream all leak results via the bulk NDJSON API (Pro only, leak scope only).

## Verification Steps

1. Do: `use auxiliary/gather/leakix_search`
1. Do: `set LEAKIX_APIKEY <your-api-key>`
1. Do: `set QUERY +country:"France" +port:3306`
1. Do: `run`
1. Verify that results are returned in a table with IP, port, protocol, host, country, organization, software, type, and source columns.

## Options

### LEAKIX_APIKEY

The LeakIX API key. Required for all actions. Free keys are available at [https://leakix.net](https://leakix.net).

### QUERY

The search query string. Required for SEARCH and BULK actions. Uses LeakIX query syntax:

- `+country:"France"` - filter by country
- `+port:3306` - filter by port
- `plugin:HttpOpenProxy` - filter by plugin name
- `+software.name:"nginx" +country:"US"` - combine filters

### SCOPE

Search scope: `leak` or `service`. Default is `leak`. The BULK action only supports `leak` scope.

### MAXPAGE

Maximum number of pages to collect for SEARCH (1-500, 20 results per page). Default is 1. The API enforces a hard limit of 500 pages regardless of plan.

### MAXRESULTS

Stop collecting after this many results. Works with SEARCH and BULK. Set to 0 (default) for unlimited.

### TARGET_IP

Target IP address for the HOST action.

### TARGET_DOMAIN

Target domain for the DOMAIN and SUBDOMAINS actions.

### OUTFILE

Path to save the results table output.

### DATABASE

Set to `true` to add discovered hosts and services to the Metasploit database.

## Scenarios

### SEARCH - Find exposed MySQL servers in France

```
msf6 > use auxiliary/gather/leakix_search
msf6 auxiliary(gather/leakix_search) > set LEAKIX_APIKEY <redacted>
LEAKIX_APIKEY => <redacted>
msf6 auxiliary(gather/leakix_search) > set QUERY +country:"France" +port:3306
QUERY => +country:"France" +port:3306
msf6 auxiliary(gather/leakix_search) > set SCOPE service
SCOPE => service
msf6 auxiliary(gather/leakix_search) > run

[*] Fetching page 1/1...
[+] Got 20 results from page 1 (total: 20)
[*] Total: 20 results

LeakIX Results
==============

 IP:Port              Protocol  Host                  Country  Organization         Software   Type     Source
 ------              --------  ----                  -------  ------------         --------   ----     ------
 x.x.x.x:3306        mysql     db.example.com        France   OVH SAS              MySQL 5.7  service  MysqlOpenPlugin
 x.x.x.x:3306        mysql     server2.example.fr    France   Online S.A.S.        MySQL 8.0  service  MysqlOpenPlugin
 ...

[*] Auxiliary module execution completed
```

### HOST - Lookup a specific IP

```
msf6 auxiliary(gather/leakix_search) > set ACTION HOST
ACTION => HOST
msf6 auxiliary(gather/leakix_search) > set TARGET_IP 1.2.3.4
TARGET_IP => 1.2.3.4
msf6 auxiliary(gather/leakix_search) > run

[*] Fetching host details for 1.2.3.4...
[*] 1.2.3.4: 3 results

LeakIX Results
==============

 IP:Port          Protocol  Host            Country        Organization  Software    Type     Source
 ------          --------  ----            -------        ------------  --------    ----     ------
 1.2.3.4:22       ssh       host.example    United States  Example Inc   OpenSSH 8   service  SshOpenPlugin
 1.2.3.4:80       http      host.example    United States  Example Inc   nginx 1.18  service  HttpOpenPlugin
 1.2.3.4:443      https     host.example    United States  Example Inc   nginx 1.18  service  HttpOpenPlugin

[*] Auxiliary module execution completed
```

### DOMAIN - Lookup a specific domain

```
msf6 auxiliary(gather/leakix_search) > set ACTION DOMAIN
ACTION => DOMAIN
msf6 auxiliary(gather/leakix_search) > set TARGET_DOMAIN example.com
TARGET_DOMAIN => example.com
msf6 auxiliary(gather/leakix_search) > run

[*] Fetching domain details for example.com...
[*] example.com: 5 results

LeakIX Results
==============

 IP:Port              Protocol  Host                  Country        Organization  Software       Type     Source
 ------              --------  ----                  -------        ------------  --------       ----     ------
 x.x.x.x:443         https     www.example.com       United States  Example Inc   nginx 1.21    service  HttpOpenPlugin
 x.x.x.x:22          ssh       mail.example.com      United States  Example Inc   OpenSSH 8.4   service  SshOpenPlugin
 ...

[*] Auxiliary module execution completed
```

### SUBDOMAINS - Enumerate subdomains

```
msf6 auxiliary(gather/leakix_search) > set ACTION SUBDOMAINS
ACTION => SUBDOMAINS
msf6 auxiliary(gather/leakix_search) > set TARGET_DOMAIN example.com
TARGET_DOMAIN => example.com
msf6 auxiliary(gather/leakix_search) > run

[*] Fetching subdomains for example.com...
[*] Found 12 subdomains

Subdomains for example.com
===========================

 Subdomain              Distinct IPs  Last Seen
 ---------              ------------  ---------
 www.example.com         2             2025-01-15T10:30:00Z
 mail.example.com        1             2025-01-14T08:22:00Z
 api.example.com         3             2025-01-15T12:00:00Z
 dev.example.com         1             2025-01-10T06:15:00Z
 ...

[*] Auxiliary module execution completed
```

### PLUGINS - List available plugins

```
msf6 auxiliary(gather/leakix_search) > set ACTION PLUGINS
ACTION => PLUGINS
msf6 auxiliary(gather/leakix_search) > run

[*] Fetching available plugins...
[*] Found 45 plugins

LeakIX Plugins
===============

 Plugin Name
 -----------
 ApacheStatusPlugin
 CouchDbOpenPlugin
 ElasticSearchOpenPlugin
 GitConfigPlugin
 HttpOpenProxy
 MongoOpenPlugin
 MysqlOpenPlugin
 SshOpenPlugin
 ...

[*] Auxiliary module execution completed
```

### BULK - Stream bulk leak results (Pro key required)

```
msf6 auxiliary(gather/leakix_search) > set ACTION BULK
ACTION => BULK
msf6 auxiliary(gather/leakix_search) > set QUERY +country:"Germany"
QUERY => +country:"Germany"
msf6 auxiliary(gather/leakix_search) > set MAXRESULTS 50
MAXRESULTS => 50
msf6 auxiliary(gather/leakix_search) > run

[*] Streaming bulk results (Pro API required, leak scope)...
[*] Streamed 50 events...
[*] Reached MAXRESULTS limit (50)
[*] Bulk results: 50 results

LeakIX Results
==============

 IP:Port              Protocol  Host                    Country  Organization         Software       Type  Source
 ------              --------  ----                    -------  ------------         --------       ----  ------
 x.x.x.x:9200        http      elastic.example.de      Germany  Hetzner Online GmbH  Elastic 7.10   leak  ElasticSearchOpenPlugin
 x.x.x.x:27017       mongodb   mongo.example.de        Germany  OVH SAS              MongoDB 4.4    leak  MongoOpenPlugin
 ...

[*] Auxiliary module execution completed
```

### Saving results to database

Set `DATABASE true` to populate the Metasploit services database with discovered hosts and services:

```
msf6 auxiliary(gather/leakix_search) > set DATABASE true
DATABASE => true
msf6 auxiliary(gather/leakix_search) > run

[*] Fetching page 1/1...
[+] Got 20 results from page 1 (total: 20)
[*] Total: 20 results
...
[*] Auxiliary module execution completed

msf6 auxiliary(gather/leakix_search) > services

Services
========

host          port   proto  name   state  info
----          ----   -----  ----   -----  ----
x.x.x.x      3306   tcp    mysql  open   MySQL 5.7
x.x.x.x      22     tcp    ssh    open   OpenSSH 8.4
...
```
