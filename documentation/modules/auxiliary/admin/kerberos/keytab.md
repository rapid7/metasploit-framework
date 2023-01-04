# keytab

Utilities for interacting with MIT keytab files, which can store the hashed passwords of one or
more principals.

Discovered keytab files can be used to generate Kerberos Ticket Granting Tickets, or bruteforced
offline.

Keytab files can be also useful for decrypting Kerberos traffic using Wireshark dissectors,
including the krbtgt encrypted blobs if the AES256 password hash is used.

## Actions

The following actions are supported:

1. **LIST** - List the entries in the keytab file [Default]
2. **ADD** - Add a new entry to the keytab file
3. **EXPORT** - Export known Kerberos encryption keys from the database

## Scenarios

### List

```
msf6 auxiliary(admin/kerberos/keytab) > run keytab_file=./example.keytab

Keytab entries
==============

 kvno  type         principal                 hash                                                              date
 ----  ----         ---------                 ----                                                              ----
 1     18 (AES256)  Administrator@ADF3.LOCAL  56c3bf6629871a4e4b8ec894f37489e823bbaecc2a0a4a5749731afa9d158e01  1970-01-01 01:00:00 +0100

[*] Auxiliary module execution completed
```

### Add

Adding an entry using a known password hash/key which has been extracted from a Domain Controller - for instance by using the `auxiliary/gather/windows_secrets_dump` module:

```
msf6 auxiliary(admin/kerberos/keytab) > run action=ADD keytab_file=./example.keytab principal=krbtgt realm=DEMO.LOCAL enctype=AES256 key=e1c5500ffb883e713288d8037651821b9ecb0dfad89e01d1b920fe136879e33c

[*] modifying existing keytab
[+] keytab entry added to ./example.keytab
```

Adding entries using a specified password:

```
msf6 auxiliary(admin/kerberos/keytab) > run action=ADD keytab_file=./example.keytab principal=Administrator realm=DEMO.LOCAL enctype=ALL password=p4$$w0rd

[*] modifying existing keytab
[*] Generating key with salt: DEMO.LOCALAdministrator. The SALT option can be set manually
[+] keytab entry added to ./example.keytab
```

### Export

Export Kerberos encryption keys stored in the Metasploit database to a keytab file. This functionality is useful in conjunction with secrets dump

```
# Secrets dump
msf6 > use auxiliary/gather/windows_secrets_dump
msf6 auxiliary(gather/windows_secrets_dump) > run smbuser=Administrator smbpass=p4$$w0rd rhosts=192.168.123.13
... ommitted ...
# Kerberos keys:
Administrator:aes256-cts-hmac-sha1-96:56c3bf6629871a4e4b8ec894f37489e823bbaecc2a0a4a5749731afa9d158e01
Administrator:aes128-cts-hmac-sha1-96:df990c21c4e8ea502efbbca3aae435ea
Administrator:des-cbc-md5:ad49d9d92f5da170
Administrator:des-cbc-crc:ad49d9d92f5da170
krbtgt:aes256-cts-hmac-sha1-96:e1c5500ffb883e713288d8037651821b9ecb0dfad89e01d1b920fe136879e33c
krbtgt:aes128-cts-hmac-sha1-96:ba87b2bc064673da39f40d37f9daa9da
krbtgt:des-cbc-md5:3ddf2f627c4cbcdc
... ommitted ...
[*] Auxiliary module execution completed

# Export to keytab
msf6 auxiliary(gather/windows_secrets_dump) > use admin/kerberos/keytab
msf6 auxiliary(admin/kerberos/keytab) > run action=EXPORT keytab_file=./example.keytab
[+] keytab saved to ./example.keytab
Keytab entries
==============

 kvno  type              principal                                   hash                                                              date
 ----  ----              ---------                                   ----                                                              ----
 1     1  (DES_CBC_CRC)  WIN11-DC3$@adf3.local                       3e5d83fe4594f261                                                  1970-01-01 01:00:00 +0100
 1     17 (AES128)       ADF3\DC3$@adf3.local                        967ccd1ffb9bff7900464b6ea383ee5b                                  1970-01-01 01:00:00 +0100
 1     3  (DES_CBC_MD5)  ADF3\DC3$@adf3.local                        62336164643537303830373630643133                                  1970-01-01 01:00:00 +0100
 1     18 (AES256)       Administrator@adf3.local                    56c3bf6629871a4e4b8ec894f37489e823bbaecc2a0a4a5749731afa9d158e01  1970-01-01 01:00:00 +0100
 1     17 (AES128)       Administrator@adf3.local                    df990c21c4e8ea502efbbca3aae435ea                                  1970-01-01 01:00:00 +0100
 1     3  (DES_CBC_MD5)  Administrator@adf3.local                    ad49d9d92f5da170                                                  1970-01-01 01:00:00 +0100
 1     1  (DES_CBC_CRC)  Administrator@adf3.local                    ad49d9d92f5da170                                                  1970-01-01 01:00:00 +0100
 1     18 (AES256)       krbtgt@adf3.local                           e1c5500ffb883e713288d8037651821b9ecb0dfad89e01d1b920fe136879e33c  1970-01-01 01:00:00 +0100
 1     17 (AES128)       krbtgt@adf3.local                           ba87b2bc064673da39f40d37f9daa9da                                  1970-01-01 01:00:00 +0100
 1     3  (DES_CBC_MD5)  krbtgt@adf3.local                           3ddf2f627c4cbcdc                                                  1970-01-01 01:00:00 +0100
... ommitted ...
[*] Auxiliary module execution completed
```

### Common Mistakes

**Invalid REALM/PRINCIPAL/SALT**

When generating a keytab with a password, a salt is generated by default from the principal and realm unless one is explicitly provided.
For Windows Active Directory environments, these values are case-sensitive. The realm should be upper case, and the principal is case-sensitive.

When the SALT is not explicitly provided a salt will be generated, for instance:

```
REALM.EXAMPLEAdministrator
```
