## Vulnerable Application

  1. [Install Oracle Database](http://www.oracle.com/technetwork/indexes/downloads/index.html#database)
  2. [Insert the "Scott/Tiger" test data](http://www.orafaq.com/wiki/SCOTT)
  
## Verification Steps

  1. Install the application
  2. Connect via sqlplus, and check current privileges: 
      1. Ex: `sqlplus SCOTT/TIGER@192.168.3.100:1521/XEXDB`
      2. Ex: `SELECT * FROM session_privs`
  2. Start msfconsole
  3. Do: ```use auxiliary/admin/oracle/oracle_index_privesc```
  4. Do: set ```SQL```, and ```TABLE``` if desired
  5. Do: ```exploit```
  6. Reconnect with sqlplus and check privileges post-exploit:
      1. Ex: `sqlplus SCOTT/TIGER@192.168.3.100:1521/XEXDB`
      2. Ex: `SELECT * FROM session_privs`

## Options

  **SQL**

  The SQL that will execute with the privileges of the user who created the index. Default is to escalate privileges.

  **TABLE**

  Table to create the index on.
