## Keytab

The `modules/auxiliary/admin/kerberos/keytab` module provides utilities for interacting with MIT keytab files, which can
store the hashed passwords of one or more principals.

Discovered keytab files can be used to generate Kerberos Ticket Granting Tickets, or bruteforced
offline.

Keytab files can be also useful for decrypting Kerberos traffic using Wireshark dissectors,
including the krbtgt encrypted blobs if the AES256 password hash is used - which is described in more detail below.

## Actions

The following actions are supported:

1. **LIST** - List the entries in the keytab file [Default]
2. **ADD** - Add a new entry to the keytab file
3. **EXPORT** - Export known Kerberos encryption keys from the database

## Scenarios

### List

```msf
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

```msf
msf6 auxiliary(admin/kerberos/keytab) > run action=ADD keytab_file=./example.keytab principal=krbtgt realm=DEMO.LOCAL enctype=AES256 key=e1c5500ffb883e713288d8037651821b9ecb0dfad89e01d1b920fe136879e33c

[*] modifying existing keytab
[+] keytab entry added to ./example.keytab
```

Adding entries using a specified password:

```msf
msf6 auxiliary(admin/kerberos/keytab) > run action=ADD keytab_file=./example.keytab principal=Administrator realm=DEMO.LOCAL enctype=ALL password=p4$$w0rd

[*] modifying existing keytab
[*] Generating key with salt: DEMO.LOCALAdministrator. The SALT option can be set manually
[+] keytab entry added to ./example.keytab
```

### Export

Export Kerberos encryption keys stored in the Metasploit database to a keytab file. This functionality is useful in conjunction with secrets dump

```msf
# Secrets dump
msf6 > use auxiliary/gather/windows_secrets_dump
msf6 auxiliary(gather/windows_secrets_dump) > run smbuser=Administrator smbpass=p4$$w0rd rhosts=192.168.123.13
... omitted ...
# Kerberos keys:
Administrator:aes256-cts-hmac-sha1-96:56c3bf6629871a4e4b8ec894f37489e823bbaecc2a0a4a5749731afa9d158e01
Administrator:aes128-cts-hmac-sha1-96:df990c21c4e8ea502efbbca3aae435ea
Administrator:des-cbc-md5:ad49d9d92f5da170
Administrator:des-cbc-crc:ad49d9d92f5da170
krbtgt:aes256-cts-hmac-sha1-96:e1c5500ffb883e713288d8037651821b9ecb0dfad89e01d1b920fe136879e33c
krbtgt:aes128-cts-hmac-sha1-96:ba87b2bc064673da39f40d37f9daa9da
krbtgt:des-cbc-md5:3ddf2f627c4cbcdc
... omitted ...
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
... omitted ...
[*] Auxiliary module execution completed
```

### Decrypting Kerberos traffic in wireshark

The Kerberos protocol makes use of encrypted values which will show as an opaque blob of hex characters in Wireshark.
Configuring Wireshark with a Keytab file can decrypt these values automatically.

For instance in a TGS-REQ request within Wireshark, the `cipher` below is encrypted using the user account's password and
is not human readable:

```
tgs-req
  pvno: 5
  msg-type: krb-tgs-req (12)
  padata: 1 item
    PA-DATA pA-TGS-REQ
      padata-type: pA-TGS-REQ (1)
        padata-value: 6e82044730820443a003020105a10302010ea20703050000000000a38203c6618203c230…
          ap-req
            pvno: 5
            msg-type: krb-ap-req (14)
            Padding: 0
            ap-options: 00000000
            ticket
            authenticator
              etype: eTYPE-ARCFOUR-HMAC-MD5 (23)
              cipher: 0bbb6dbc29413df5905d45c97a3d05239bd609326ff4a410f47048c3f4e22c3ea8003985…
                      ^^^^^^^^^^^^^^ Value encrypted using the user account's password
```

The easiest way to decrypt these opaque blobs is to generate a Keytab file with Metasploit using the secretsdump scenario above or similar.
After generating a keytab file in the Wireshark GUI go to `Edit -> Preferences -> Protocols -> KRB5` and modify the following options:
- Set `try to decrypt Kerberos blobs` to true
- Set the `Kerebros keytab file` to the keytab file generated by your domain controller

After confirming the new settings - the previously encrypted which were signed with the user's password, and the decryptable session key
should be viewable in Wireshark.

For example the previous TGS-REQ authenticator blob is now decrypted in the Wireshark UI. Wireshark on Linux may not show
the decrypted packet information in the packet details pane, instead it appears as a separate tab in the packet bytes pane:

```
tgs-req
  pvno: 5
  msg-type: krb-tgs-req (12)
  padata: 1 item
    PA-DATA pA-TGS-REQ
      padata-type: pA-TGS-REQ (1)
        padata-value: 6e82044730820443a003020105a10302010ea20703050000000000a38203c6618203c230…
          ap-req
            pvno: 5
            msg-type: krb-ap-req (14)
            Padding: 0
            ap-options: 00000000
            ticket
            authenticator
              etype: eTYPE-ARCFOUR-HMAC-MD5 (23)
              cipher: 0bbb6dbc29413df5905d45c97a3d05239bd609326ff4a410f47048c3f4e22c3ea8003985…
                Decrypted keytype 23 usage 7 using learnt encASRepPart_key in frame 475 (id=475.1 same=0) (f161f360...)
                  # ...
                authenticator
                  authenticator-vno: 5
                  crealm: ADF3.LOCAL
                  cname
                    name-type: kRB5-NT-PRINCIPAL (1)
                    cname-string: 1 item
                      CNameString: a
                  cusec: 303247
                  ctime: 2022-04-10 15:21:31 (UTC)
                  ^^^^^^^^^^^^^^ authenticator value now decrypted using the previously generated keytab file
```

If you have exported the `krbtgt` account to the keytab file - Wireshark will also decrypt the TGT ticket itself. If not - Wireshark
will generate warnings about being unable to decrypt the TGT ticket which is signed using the krbtgt account.

Additional details: https://wiki.wireshark.org/Kerberos

If you are on a Windows domain controller it is possible to use the `ktpass` program to generate keytab files: 

```
ktpass /crypto All /princ Administrator@DEMO.LOCAL /pass p4$$w0rd /out demo.keytab /ptype KRB5_NT_PRINCIPAL
```

It is easier to use the Metasploit module, but if you do use ktpass - be aware of the following issues:
- If the password contains `$` it is easier to run the `ktpass` command in `cmd` rather than `powershell` to avoid unexpected variable substitution
- If there is a `Missing keytype 18` warning for `etype: eTYPE-AES256-CTS-HMAC-SHA1-96 (18)` in Wireshark - verify that the principal name is correct within the ktpass generation command
  - This should match the initial AS-REQ KRB ERROR salt, found in `krb-error` -> `edata` -> `ETYPE-INFO2-ENTRY` -> `salt`

### Common Mistakes

**Invalid REALM/PRINCIPAL/SALT**

When generating a keytab with a password, a salt is generated by default from the principal and realm unless one is explicitly provided.
For Windows Active Directory environments, these values are case-sensitive. The realm should be upper case, and the principal is case-sensitive.

When the SALT is not explicitly provided a salt will be generated that follows the Windows naming convention, for instance:

```
REALM.EXAMPLEAdministrator
```
