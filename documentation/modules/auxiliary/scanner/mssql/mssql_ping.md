## Description

The `mssql_ping` module queries a host or range of hosts on UDP port 1434 to determine the listening TCP port of any MSSQL server, if available. MSSQL randomizes the TCP port that it listens on so this is a very valuable module in the Framework.

## Verification Steps

1. Do: ```use auxiliary/scanner/mssql/mssql_ping```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set THREADS [number of threads]```
4. Do: ```run```

## Scenarios

```
msf > use auxiliary/scanner/mssql/mssql_ping
msf auxiliary(mssql_ping) > set RHOSTS 192.168.1.200-254
RHOSTS => 192.168.1.200-254
msf auxiliary(mssql_ping) > set THREADS 20
THREADS => 20
msf auxiliary(mssql_ping) > run

[*] Scanned 13 of 55 hosts (023% complete)
[*] Scanned 16 of 55 hosts (029% complete)
[*] Scanned 17 of 55 hosts (030% complete)
[*] SQL Server information for 192.168.1.217:
[*]    tcp             = 27900
[*]    np              = \\SERVER2\pipe\sql\query
[*]    Version         = 8.00.194
[*]    InstanceName    = MSSQLSERVER
[*]    IsClustered     = No
[*]    ServerName      = SERVER2
[*] SQL Server information for 192.168.1.241:
[*]    tcp             = 1433
[*]    np              = \\2k3\pipe\sql\query
[*]    Version         = 8.00.194
[*]    InstanceName    = MSSQLSERVER
[*]    IsClustered     = No
[*]    ServerName      = 2k3
[*] Scanned 32 of 55 hosts (058% complete)
[*] Scanned 40 of 55 hosts (072% complete)
[*] Scanned 44 of 55 hosts (080% complete)
[*] Scanned 45 of 55 hosts (081% complete)
[*] Scanned 46 of 55 hosts (083% complete)
[*] Scanned 50 of 55 hosts (090% complete)
[*] Scanned 55 of 55 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(mssql_ping) >
```
