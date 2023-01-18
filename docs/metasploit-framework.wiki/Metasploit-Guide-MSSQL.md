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

