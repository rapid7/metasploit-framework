## MSSQL Workflows

Microsoft SQL Server (MSSQL) is a relational database management system. Commonly used in conjunction with web applications
and other software that need to persist data. MSSQL is a useful target for data extraction and code execution.

MySQL is frequently found on port on the following ports:

- 1433/TCP
- 1434/UDP

### Lab Environment

Environment setup:

- Either follow [Microsoft's SQL Server installation guide](https://learn.microsoft.com/en-us/sql/database-engine/install-windows/install-sql-server?view=sql-server-ver16) or use chocolatey package manager 
- Enable TCP access within the SQL Server Configuration Manager
- Optional: [Microsoft's sqlcmd utility](https://docs.microsoft.com/en-us/sql/tools/sqlcmd-utility?view=sql-server-ver16) can be installed separately for querying the database from your host machine
- Optional: [Configure Windows firewall](https://learn.microsoft.com/en-us/sql/sql-server/install/configure-the-windows-firewall-to-allow-sql-server-access?view=sql-server-ver16) to allow MSSQL server access 

### MSSQL Enumeration

### Running queries

```
use auxiliary/admin/mssql/mssql_sql
run rhost=192.168.123.13 username=administrator password=p4$$w0rd sql='select auth_scheme from sys.dm_exec_connections where session_id=@@spid'
```

### Link crawling

Identify if the SQL server has been configured with trusted links, which allows running queries on other MSSQL instances:

```
use windows/mssql/mssql_linkcrawler
run rhost=192.168.123.13 username=administrator password=p4$$w0rd
```

### Kerberos Authentication

Details on the Kerberos specific option names are documented in [[Kerberos Service Authentication|kerberos/service_authentication]]

Connect to a Microsoft SQL Server instance and run a query:

```msf
msf6 > use auxiliary/admin/mssql/mssql_sql
msf6 auxiliary(admin/mssql/mssql_sql) > run 192.168.123.13 domaincontrollerrhost=192.168.123.13 username=administrator password=p4$$w0rd mssql::auth=kerberos mssql::rhostname=dc3.demo.local mssqldomain=demo.local sql='select auth_scheme from sys.dm_exec_connections where session_id=@@spid'
[*] Reloading module...
[*] Running module against 192.168.123.13

[*] 192.168.123.13:1433 - 192.168.123.13:88 - Valid TGT-Response
[+] 192.168.123.13:1433 - 192.168.123.13:88 - Valid TGS-Response
[*] 192.168.123.13:1433 - 192.168.123.13:88 - TGS MIT Credential Cache saved to ~/.msf4/loot/20220630193907_default_192.168.123.13_windows.kerberos_556101.bin
[*] 192.168.123.13:1433 - SQL Query: select auth_scheme from sys.dm_exec_connections where session_id=@@spid
[*] 192.168.123.13:1433 - Row Count: 1 (Status: 16 Command: 193)

 auth_scheme
 -----------
 KERBEROS

[*] Auxiliary module execution completed
```
