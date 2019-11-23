## Vulnerable Application

This module queries a DB2 instance information.

More information can be found on the [Rapid7 Vulnerability & Exploit Database page](https://www.rapid7.com/db/modules/auxiliary/scanner/db2/db2_version)

## Verification Steps

  1. Start msfconsole
  2. Do: `use auxiliary/scanner/db2/db2_version`
  3. Do: `set RHOSTS [ip]`
  3. Do: `run`

## Scenarios

##  A run on Kali Linux 2019.3 and DB2 11.5.0.0a

  ```
  msf > use auxiliary/scanner/db2/db2_version
  msf auxiliary(scanner/db2/db2_version) > show options
  msf auxiliary(scanner/db2/db2_version) > set DATABASE testdb
  msf auxiliary(scanner/db2/db2_version) > set RHOSTS 172.17.0.2
  msf auxiliary(scanner/db2/db2_version) > run
    [+] 172.17.0.2:50000      - 172.17.0.2:50000 DB2 - Platform: QDB2/LINUXX8664, Version: SQL11050, Instance: db2inst1, Plain-Authentication: OK
    [*] 172.17.0.2:50000      - Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed
  ```
