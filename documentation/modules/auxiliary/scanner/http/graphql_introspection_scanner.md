## Vulnerable Application

This module scans GraphQL endpoints to check if they have enabled introspection.
This allows for gathering the schema for the endpoint, potentially leading to information disclosure.
The module stores this as a vulnerability, and can also store the dumped schema as loot.

### Creating a Vulnerable Environment
You can either target a public GraphQL endpoint present here: https://github.com/graphql-kit/graphql-apis
Or set up a local server by following a tutorial here: https://www.apollographql.com/docs/apollo-server/getting-started

## Options

### TARGETURI

The GraphQL endpoint URI, which will receive the POST requests.

## Verification Steps

1. Do: run `msfconsole`
2. Do: use `auxiliary/scanner/http/graphql_introspection_scanner`
3. Do: set `RHOSTS [IP]`
4. Do: set `TARGETURI [URI]`
5. Do: `run`

## Scenarios

### Apollo Server - JavaScript
```
auxiliary(scanner/http/graphql_introspection_scanner) > check rport=4001
[+] 127.0.0.1:4001 - The target is vulnerable. The server has introspection enabled.

auxiliary(scanner/http/graphql_introspection_scanner) > run rport=4001
[*] Running module against 127.0.0.1
[+] 127.0.0.1:4001 - Server responded with introspected data. Reporting a vulnerability, and storing it as loot.
[*] Auxiliary module execution completed

auxiliary(scanner/http/graphql_introspection_scanner) > vulns

Vulnerabilities
===============

Timestamp                Host       Name                                                  References
---------                ----       ----                                                  ----------
2025-05-27 16:12:25 UTC  127.0.0.1  GraphQL Information Disclosure through Introspection  URL-https://portswigger.net/web-security/graphql,URL-https://graphql.o
                                                                                          rg/learn/introspection/
2025-05-27 16:12:34 UTC  127.0.0.1  GraphQL Introspection Scanner                         URL-https://portswigger.net/web-security/graphql,URL-https://graphql.o
                                                                                          rg/learn/introspection/
```

### Graphloc
```
auxiliary(scanner/http/graphql_introspection_scanner) > run rhost=https://graphloc.com/
[*] Running module against 151.101.1.195
[*] 151.101.1.195:443 - Server responded with introspected data. Reporting a vulnerability, and storing it as loot.
```

### catalysis-hub
```
uxiliary(scanner/http/graphql_introspection_scanner) > run rhost=https://api.catalysis-hub.org/graphql?
[*] Running module against 3.33.161.45
[*] 3.33.161.45:443 - Server responded with introspected data. Reporting a vulnerability, and storing it as loot.
```
