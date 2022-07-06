## Vulnerable Application
This module allows users to query an LDAP server using either a custom LDAP query, or
a set of LDAP queries under a specific category. Users can also specify a JSON or 
YAML file containing custom queries to be executed using the RUN_QUERY_FILE action. 
If this action is specified, then `QUERY_FILE_PATH` must be a path to the 
location of this JSON/YAML file on disk.

Alternatively one can run one of several predefined queries by setting ACTION to the
appropriate value.

All results will be returned to the user in table format, with `||` as the delimiter
separating multiple items within one column.

## Verification Steps

1. Do: `use auxiliary/gather/ldap_query`
2. Do: `set ACTION <target action>`
3. Do: `set RHOSTS <target IP(s)>`
4. Optional: `set RPORT <target port>` if target port is non-default.
5: Optional: `set SSL true` if the target port is SSL enabled.
6: Do: `run`

## Scenarios

### ENUM_COMPUTERS with Table Output

```
msf6 payload(windows/x64/meterpreter/reverse_tcp) > use auxiliary/gather/ldap_query
msf6 auxiliary(gather/ldap_query) > show options

Module options (auxiliary/gather/ldap_query):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   BASE_DN                         no        LDAP base DN if you already have it
   BIND_DN                         no        The username to authenticate to LDAP server
   BIND_PW                         no        Password for the BIND_DN
   OUTPUT_FORMAT  table            yes       The output format to use (Accepted: csv, table, json)
   RHOSTS                          yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-M
                                             etasploit
   RPORT          389              yes       The target port
   SSL            false            no        Enable SSL on the LDAP connection

msf6 auxiliary(gather/ldap_query) > set ACTION 
set ACTION ENUM_ACCOUNTS             set ACTION ENUM_DOMAIN_CONTROLLERS   set ACTION ENUM_ORGROLES
set ACTION ENUM_ALL_OBJECT_CATEGORY  set ACTION ENUM_EXCHANGE_RECIPIENTS  set ACTION ENUM_ORGUNITS
set ACTION ENUM_ALL_OBJECT_CLASS     set ACTION ENUM_EXCHANGE_SERVERS     set ACTION RUN_QUERY_FILE
set ACTION ENUM_COMPUTERS            set ACTION ENUM_GROUPS               
msf6 auxiliary(gather/ldap_query) > set ACTION ENUM_COMPUTERS 
ACTION => ENUM_COMPUTERS
msf6 auxiliary(gather/ldap_query) > set RHOSTS 172.20.161.209
RHOSTS => 172.20.161.209
msf6 auxiliary(gather/ldap_query) > set BIND_PW thePassword123
BIND_PW => thePassword123
msf6 auxiliary(gather/ldap_query) > set BIND_DN normal@daforest.com
BIND_DN => normal@daforest.com
msf6 auxiliary(gather/ldap_query) > run
[*] Running module against 172.20.161.209

[+] Successfully bound to the LDAP server!
[*] Discovering base DN automatically
[+] 172.20.161.209:389 Discovered base DN: DC=daforest,DC=com
[*] CN=WIN-F7DQC9SR0HD OU=Domain Controllers DC=daforest DC=com
===========================================================

 Name                    Attributes
 ----                    ----------
 distinguishedname       CN=WIN-F7DQC9SR0HD,OU=Domain Controllers,DC=daforest,DC=com
 dnshostname             WIN-F7DQC9SR0HD.daforest.com
 name                    WIN-F7DQC9SR0HD
 operatingsystemversion  10.0 (20348)

[*] CN=FSRWLPT1000000 OU=Testing DC=daforest DC=com
===============================================

 Name               Attributes
 ----               ----------
 description        Created with secframe.com/badblood.
 displayname        FSRWLPT1000000
 distinguishedname  CN=FSRWLPT1000000,OU=Testing,DC=daforest,DC=com
 name               FSRWLPT1000000

[*] CN=TSTWVIR1000000 OU=FSR OU=People DC=daforest DC=com
=====================================================

 Name               Attributes
 ----               ----------
 description        Created with secframe.com/badblood.
 displayname        TSTWVIR1000000
 distinguishedname  CN=TSTWVIR1000000,OU=FSR,OU=People,DC=daforest,DC=com
 name               TSTWVIR1000000

*cut for brevity*

[*] CN=WVIR1000013 OU=Test OU=BDE OU=Tier 2 DC=daforest DC=com
==========================================================

 Name               Attributes
 ----               ----------
 description        Created with secframe.com/badblood.
 displayname        WVIR1000013
 distinguishedname  CN=WVIR1000013,OU=Test,OU=BDE,OU=Tier 2,DC=daforest,DC=com
 name               WVIR1000013

[*] Auxiliary module execution completed
msf6 auxiliary(gather/ldap_query) > 
```

### ENUM_COMPUTERS with CSV Output
```
msf6 payload(windows/x64/meterpreter/reverse_tcp) > use auxiliary/gather/ldap_query             
msf6 auxiliary(gather/ldap_query) > set ACTION ENUM_COMPUTERS 
ACTION => ENUM_COMPUTERS
msf6 auxiliary(gather/ldap_query) > set RHOSTS 172.20.161.209
RHOSTS => 172.20.161.209
msf6 auxiliary(gather/ldap_query) > set BIND_PW thePassword123
BIND_PW => thePassword123
msf6 auxiliary(gather/ldap_query) > set BIND_DN normal@daforest.com
BIND_DN => normal@daforest.com
msf6 auxiliary(gather/ldap_query) > set OUTPUT_FORMAT csv 
OUTPUT_FORMAT => csv
msf6 auxiliary(gather/ldap_query) > show options

Module options (auxiliary/gather/ldap_query):

   Name           Current Setting      Required  Description
   ----           ---------------      --------  -----------
   BASE_DN                             no        LDAP base DN if you already have it
   BIND_DN        normal@daforest.com  no        The username to authenticate to LDAP server
   BIND_PW        thePassword123       no        Password for the BIND_DN
   OUTPUT_FORMAT  csv                  yes       The output format to use (Accepted: csv, table, json)
   RHOSTS         172.20.161.209       yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Usi
                                                 ng-Metasploit
   RPORT          389                  yes       The target port
   SSL            false                no        Enable SSL on the LDAP connection


Auxiliary action:

   Name            Description
   ----            -----------
   ENUM_COMPUTERS  Dump all objects containing an objectCategory of Computer.


msf6 auxiliary(gather/ldap_query) > run
[*] Running module against 172.20.161.209

[+] Successfully bound to the LDAP server!
[*] Discovering base DN automatically
[+] 172.20.161.209:389 Discovered base DN: DC=daforest,DC=com
[*] Name,Attributes
"dn","CN=WIN-F7DQC9SR0HD,OU=Domain Controllers,DC=daforest,DC=com"
"distinguishedname","CN=WIN-F7DQC9SR0HD,OU=Domain Controllers,DC=daforest,DC=com"
"name","WIN-F7DQC9SR0HD"
"operatingsystemversion","10.0 (20348)"
"dnshostname","WIN-F7DQC9SR0HD.daforest.com"

[*] Name,Attributes
"dn","CN=FSRWLPT1000000,OU=Testing,DC=daforest,DC=com"
"description","Created with secframe.com/badblood."
"distinguishedname","CN=FSRWLPT1000000,OU=Testing,DC=daforest,DC=com"
"displayname","FSRWLPT1000000"
"name","FSRWLPT1000000"

[*] Name,Attributes
"dn","CN=TSTWVIR1000000,OU=FSR,OU=People,DC=daforest,DC=com"
"description","Created with secframe.com/badblood."
"distinguishedname","CN=TSTWVIR1000000,OU=FSR,OU=People,DC=daforest,DC=com"
"displayname","TSTWVIR1000000"
"name","TSTWVIR1000000"

*cut for brevity*

[*] Name,Attributes
"dn","CN=WVIR1000013,OU=Test,OU=BDE,OU=Tier 2,DC=daforest,DC=com"
"description","Created with secframe.com/badblood."
"distinguishedname","CN=WVIR1000013,OU=Test,OU=BDE,OU=Tier 2,DC=daforest,DC=com"
"displayname","WVIR1000013"
"name","WVIR1000013"

[*] Auxiliary module execution completed
msf6 auxiliary(gather/ldap_query) > 
```

### ENUM_COMPUTERS with JSON Output
```
msf6 payload(windows/x64/meterpreter/reverse_tcp) > use auxiliary/gather/ldap_query             
msf6 auxiliary(gather/ldap_query) > set ACTION ENUM_COMPUTERS 
ACTION => ENUM_COMPUTERS
msf6 auxiliary(gather/ldap_query) > set RHOSTS 172.20.161.209
RHOSTS => 172.20.161.209
msf6 auxiliary(gather/ldap_query) > set BIND_PW thePassword123
BIND_PW => thePassword123
msf6 auxiliary(gather/ldap_query) > set BIND_DN normal@daforest.com
BIND_DN => normal@daforest.com
msf6 auxiliary(gather/ldap_query) > set OUTPUT_FORMAT json 
OUTPUT_FORMAT => json
msf6 auxiliary(gather/ldap_query) > show options

Module options (auxiliary/gather/ldap_query):

   Name           Current Setting      Required  Description
   ----           ---------------      --------  -----------
   BASE_DN                             no        LDAP base DN if you already have it
   BIND_DN        normal@daforest.com  no        The username to authenticate to LDAP server
   BIND_PW        thePassword123       no        Password for the BIND_DN
   OUTPUT_FORMAT  json                 yes       The output format to use (Accepted: csv, table, json)
   RHOSTS         172.20.161.209       yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Usi
                                                 ng-Metasploit
   RPORT          389                  yes       The target port
   SSL            false                no        Enable SSL on the LDAP connection


Auxiliary action:

   Name            Description
   ----            -----------
   ENUM_COMPUTERS  Dump all objects containing an objectCategory of Computer.


msf6 auxiliary(gather/ldap_query) > run
[*] Running module against 172.20.161.209

[+] Successfully bound to the LDAP server!
[*] Discovering base DN automatically
[+] 172.20.161.209:389 Discovered base DN: DC=daforest,DC=com
[*] CN=WIN-F7DQC9SR0HD OU=Domain Controllers DC=daforest DC=com
{
  "dn": "CN=WIN-F7DQC9SR0HD,OU=Domain Controllers,DC=daforest,DC=com",
  "distinguishedname": "CN=WIN-F7DQC9SR0HD,OU=Domain Controllers,DC=daforest,DC=com",
  "name": "WIN-F7DQC9SR0HD",
  "operatingsystemversion": "10.0 (20348)",
  "dnshostname": "WIN-F7DQC9SR0HD.daforest.com"
}
[*] CN=FSRWLPT1000000 OU=Testing DC=daforest DC=com
{
  "dn": "CN=FSRWLPT1000000,OU=Testing,DC=daforest,DC=com",
  "description": "Created with secframe.com/badblood.",
  "distinguishedname": "CN=FSRWLPT1000000,OU=Testing,DC=daforest,DC=com",
  "displayname": "FSRWLPT1000000",
  "name": "FSRWLPT1000000"
}
[*] CN=TSTWVIR1000000 OU=FSR OU=People DC=daforest DC=com
{
  "dn": "CN=TSTWVIR1000000,OU=FSR,OU=People,DC=daforest,DC=com",
  "description": "Created with secframe.com/badblood.",
  "distinguishedname": "CN=TSTWVIR1000000,OU=FSR,OU=People,DC=daforest,DC=com",
  "displayname": "TSTWVIR1000000",
  "name": "TSTWVIR1000000"
}
*cut for brevity*
[*] CN=WLPT1000014 OU=AZR OU=Stage DC=daforest DC=com
{
  "dn": "CN=WLPT1000014,OU=AZR,OU=Stage,DC=daforest,DC=com",
  "description": "Created with secframe.com/badblood.",
  "distinguishedname": "CN=WLPT1000014,OU=AZR,OU=Stage,DC=daforest,DC=com",
  "displayname": "WLPT1000014",
  "name": "WLPT1000014"
}
[*] CN=WWKS1000016 OU=T1-Roles OU=Tier 1 OU=Admin DC=daforest DC=com
{
  "dn": "CN=WWKS1000016,OU=T1-Roles,OU=Tier 1,OU=Admin,DC=daforest,DC=com",
  "description": "Created with secframe.com/badblood.",
  "distinguishedname": "CN=WWKS1000016,OU=T1-Roles,OU=Tier 1,OU=Admin,DC=daforest,DC=com",
  "displayname": "WWKS1000016",
  "name": "WWKS1000016"
}
[*] CN=WVIR1000013 OU=Test OU=BDE OU=Tier 2 DC=daforest DC=com
{
  "dn": "CN=WVIR1000013,OU=Test,OU=BDE,OU=Tier 2,DC=daforest,DC=com",
  "description": "Created with secframe.com/badblood.",
  "distinguishedname": "CN=WVIR1000013,OU=Test,OU=BDE,OU=Tier 2,DC=daforest,DC=com",
  "displayname": "WVIR1000013",
  "name": "WVIR1000013"
}
[*] Auxiliary module execution completed
msf6 auxiliary(gather/ldap_query) > 
```