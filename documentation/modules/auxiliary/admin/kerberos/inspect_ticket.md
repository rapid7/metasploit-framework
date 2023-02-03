## Inspecting Kerberos Tickets

The `auxiliary/admin/kerberos/inspect_ticket` module allows you to print the contents of a ccache/kirbi file.
The module will output ticket information such as:

- Client information
- Service information
- Ticket creation / expiry times
- Decrypted ticket contents - if `NTHASH` or `AESKEY` is set

## Acquiring tickets

Kerberos tickets can be acquired from multiple sources. For instance:

- Retrieved directly from the KDC with the `get_ticket` module
- Forged using the `forge_ticket` module after compromising the krbtgt or a service account's encryption keys
- Extracted from memory using Meterpreter and mimikatz:

```msf
meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.

meterpreter > kiwi_cmd "sekurlsa::tickets /export"

Authentication Id : 0 ; 1393218 (00000000:00154242)
Session           : Network from 0
User Name         : DC3$
Domain            : DEMO
Logon Server      : (null)
Logon Time        : 1/12/2023 9:11:00 PM
SID               : S-1-5-18

	 * Username : DC3$
	 * Domain   : DEMO.LOCAL
	 * Password : (null)

	Group 0 - Ticket Granting Service

	Group 1 - Client Ticket ?
	 [00000000]
	   Start/End/MaxRenew: 1/12/2023 7:41:41 PM ; 1/13/2023 5:37:45 AM ; 1/1/1601 12:00:00 AM
	   Service Name (02) : LDAP ; DC3 ; @ DEMO.LOCAL
	   Target Name  (--) : @ DEMO.LOCAL
	   Client Name  (01) : DC3$ ; @ DEMO.LOCAL
	   Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
	   Session Key       : 0x00000012 - aes256_hmac
	     ab64d555f18de6a3262d921e6dc75dcf884852f551db3114f7983dbaf276e1d6
	   Ticket            : 0x00000012 - aes256_hmac       ; kvno = 7	[...]
====================
Base64 of file : [0;154242]-1-0-40a50000-DC3$@LDAP-DC3.kirbi
====================
doQAAAYXMIQAAAYRoIQAAAADAgEFoYQAAAADAgEWooQAAAS2MIQAAASwYYQAAASq
MIQAAASkoIQAAAADAgEFoYQAAAAMGwpBREYzLkxPQ0FMooQAAAAmMIQAAAAgoIQA
AAADAgECoYQAAAARMIQAAAALGwRMREFQGwNEQzOjhAAABFcwhAAABFGghAAAAAMC
... etc...
====================
```

Note that tools often Base64 encode the Kirbi content to display to the user. However the `inspect_ticket` module expects
the input file to be in binary format. To convert base64 strings to binary files:

```
# Linux
cat ticket.b64 | base64 -d > ticket.kirbi

# Mac
cat ticket.b64 | base64 -D > ticket.kirbi

# Powershell
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<bas64_ticket>"))
```

## Module usage

1. Start msfconsole
2. Do: `use auxiliary/admin/kerberos/inspect_ticket`
3. Do: `set TICKET_PATH /path/to/ccache/file`
4. Optional: either `set AES_KEY aes_key_here` or `set NTHASH nthash_here` - which will attempt to decrypt tickets
5. Do: `run` to see the contents of the ticket

## Scenarios

### Inspecting Ticket contents

This action allows you to see the contents of any ccache or kirbi file,
If you are able to provide the decryption key we can also show the encrypted parts of the tickets.

1. `TICKET_PATH` - The path to the ccache or kirbi file.
2. `AES_KEY` - (Optional) Only set this if you have the decryption key and it is an AES128 or AES256 key.
3. `NTHASH` - (Optional) Only set this if you have the decryption key and it is an NTHASH.
No other options are used in this action.

**Without Key**

```msf
msf6 auxiliary(admin/kerberos/inspect_ticket) > run TICKET_PATH=/path/to/ticket
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

**With Key**

```msf
msf6 auxiliary(admin/kerberos/inspect_ticket) > run AES_KEY=4b912be0366a6f37f4a7d571bee18b1173d93195ef76f8d1e3e81ef6172ab326 TICKET_PATH=/path/to/ticket
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

Both of these examples are printing the contents of the same ccache file and showing the difference in output if you have the decryption key available.
