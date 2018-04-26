
## About

This module simply queries the DB2 discovery service for information.
The discovery service is integrated with the Configuration Assistant and the DB2® administration server.
Using the discovery method, catalog information for a remote server can be automatically generated in the local database and node directory.

## Verification Steps

To test this module, you must make sure there is at least one reacheable DB2 Discovery Service at the target address range or CIDR identifier.
1. `use auxiliary/scanner/db2/discovery`
2. `set RHOSTS [target address range/cidr]`
3. `set THREDS [number of threads]`
4. `run`


## Scenarios

```
msf auxiliary(scanner/db2/discovery) > set RHOSTS 192.168.1.25
msf auxiliary(scanner/db2/discovery) > run

[+] Host 192.168.1.25 node name is SERVER02 with a product id of SQL090__
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

msf auxiliary(scanner/db2/discovery) > 
```