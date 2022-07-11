## Vulnerable Application
This module allows users to query an LDAP server using either a custom LDAP query, or
a set of LDAP queries under a specific category. Users can also specify a JSON or YAML
file containing custom queries to be executed using the `RUN_QUERY_FILE` action.
If this action is specified, then `QUERY_FILE_PATH` must be a path to the location
of this JSON/YAML file on disk.

Users can also run a single query by using the `RUN_SINGLE_QUERY` option and then setting
the `QUERY_FILTER` datastore option to the filter to send to the LDAP server and `QUERY_ATTRIBUTES`
to a comma seperated string containing the list of attributes they are interested in obtaining
from the results.

As a third option can run one of several predefined queries by setting `ACTION` to the
appropriate value. These options will be loaded from the `ldap_queries_default.yaml` file
located in the MSF configuration directory, located by default at `~/.msf4/ldap_queries_default.yaml`.

Note that you can override the default query settings in this way by defining a query with an
action name that is the same as one of existing actions in the file at
`data/auxiliary/gather/ldap_query/ldap_queries_default.yaml`. This will however prevent any updates
for that action that may be made to the `data/auxiliary/gather/ldap_query/ldap_queries_default.yaml`
file, which may occur as part of Metasploit updates/upgrades, from being used though, so keep this
in mind when using the `~/.msf4/ldap_queries_default.yaml` file.

All results will be returned to the user in table, CSV or JSON format, depending on the value
of the `OUTPUT_FORMAT` datastore option. The characters `||` will be used as a delimiter
should multiple items exist within a single column.

## Verification Steps

1. Do: `use auxiliary/gather/ldap_query`
2. Do: `set ACTION <target action>`
3. Do: `set RHOSTS <target IP(s)>`
4. Optional: `set RPORT <target port>` if target port is non-default.
5: Optional: `set SSL true` if the target port is SSL enabled.
6: Do: `run`

## Options

### OUTPUT_FORMAT
The output format to use. Can be either `csv`, `table` or `json` for
CSV, Rex table output, or JSON output respectively.

### BASE_DN
The LDAP base DN if already obtained. If not supplied, the module will
automatically attempt to find the base DN for the target LDAP server.

### QUERY_FILE_PATH
If the `ACTION` is set to `RUN_QUERY_FILE`, then this option is required and
must be set to the full path to the JSON or YAML file containing the queries to
be run.

The file format must follow the following convention:

```
queries:
  - action: THE ACTION NAME
    description: "THE ACTION DESCRIPTION"
    filter: "THE LDAP FILTER"
    attributes:
      - dn
      - displayName
      - name
      - description
```

Where `queries` is an array of queries to be run, each containing an `action` field
containing the name of the action to be run, a `description` field describing the
action, a `filter` field containing the filter to send to the LDAP server
(aka what to search on), and the list of attributes that we are interested in from
the results as an array.

### QUERY_FILTER
Used only when the `RUN_SINGLE_QUERY` action is used. This should be set to the filter
aka query that you want to send to the target LDAP server.

### QUERY_ATTRIBUTES
Used only when the `RUN_SINGLE_QUERY` action is used. Should be a comma separated list
of attributes to display from the full result set for each entry that was returned by the
target LDAP server. Used to filter the results down to manageable sets of data.

## Scenarios

### RUN_SINGLE_QUERY with Table Output

```
msf6 payload(windows/x64/meterpreter/reverse_tcp) > use auxiliary/gather/ldap_query 
msf6 auxiliary(gather/ldap_query) > set BIND_DN normal@daforest.com
BIND_DN => normal@daforest.com
msf6 auxiliary(gather/ldap_query) > set BIND_PW thePassword123
BIND_PW => thePassword123
msf6 auxiliary(gather/ldap_query) > set RHOSTS 172.27.51.83
RHOSTS => 172.27.51.83
msf6 auxiliary(gather/ldap_query) > set ACTION RUN_SINGLE_QUERY
ACTION => RUN_SINGLE_QUERY
msf6 auxiliary(gather/ldap_query) > set QUERY_ATTRIBUTES dn,displayName,name
QUERY_ATTRIBUTES => dn,displayName,name
msf6 auxiliary(gather/ldap_query) > set QUERY_FILTER (objectClass=*)
QUERY_FILTER => (objectClass=*)
msf6 auxiliary(gather/ldap_query) > run
[*] Running module against 172.27.51.83

[+] Successfully bound to the LDAP server!
[*] Discovering base DN automatically
[+] 172.27.51.83:389 Discovered base DN: DC=daforest,DC=com
[*] Sending single query (objectClass=*) to the LDAP server...
[*] DC=daforest DC=com
==================

 Name  Attributes
 ----  ----------
 name  daforest

[*] CN=Users DC=daforest DC=com
===========================

 Name  Attributes
 ----  ----------
 name  Users

[*] CN=Computers DC=daforest DC=com
===============================

 Name  Attributes
 ----  ----------
 name  Computers

*cut for brevity*

[*] CN=WAPPS1000022 OU=TST OU=Tier 1 DC=daforest DC=com
===================================================

 Name         Attributes
 ----         ----------
 displayname  WAPPS1000022
 name         WAPPS1000022

[*] CN=WLPT1000014 OU=AZR OU=Stage DC=daforest DC=com
=================================================

 Name         Attributes
 ----         ----------
 displayname  WLPT1000014
 name         WLPT1000014

[*] CN=WWKS1000016 OU=T1-Roles OU=Tier 1 OU=Admin DC=daforest DC=com
================================================================

 Name         Attributes
 ----         ----------
 displayname  WWKS1000016
 name         WWKS1000016

[*] CN=WVIR1000013 OU=Test OU=BDE OU=Tier 2 DC=daforest DC=com
==========================================================

 Name         Attributes
 ----         ----------
 displayname  WVIR1000013
 name         WVIR1000013
 
[*] Auxiliary module execution completed
msf6 auxiliary(gather/ldap_query) > 
```

### RUN_QUERY_FILE with Table Output

Here is the sample query file we will be using:

```
$ cat test.yaml
---
queries:
  - action: ENUM_USERS
    description: "Enumerate users"
    filter: "(|(objectClass=inetOrgPerson)(objectClass=user)(sAMAccountType=805306368)(objectClass=posixAccount))"
    columns:
      - dn
      - displayName
      - name
      - description
  - action: ENUM_ORGUNITS
    description: "Enumerate organizational units"
    filter: "(objectClass=organizationalUnit)"
    columns:
      - dn
      - displayName
      - name
      - description
  - action: ENUM_GROUPS
    description: "Enumerate groups"
    filter: "(|(objectClass=group)(objectClass=groupOfNames)(groupType:1.2.840.113556.1.4.803:=2147483648)(objectClass=posixGroup))"
    columns:
      - dn
      - name
      - groupType
      - memberof
```

Here is the results of using this file with the `RUN_QUERY_FILE` action which will
run all queries within the file one after another.

```
msf6 payload(windows/x64/meterpreter/reverse_tcp) > use auxiliary/gather/ldap_query 
msf6 auxiliary(gather/ldap_query) > set BIND_DN normal@daforest.com
BIND_DN => normal@daforest.com
msf6 auxiliary(gather/ldap_query) > set BIND_PW thePassword123
BIND_PW => thePassword123
msf6 auxiliary(gather/ldap_query) > set RHOSTS 172.27.51.83
RHOSTS => 172.27.51.83
msf6 auxiliary(gather/ldap_query) > set ACTION RUN_QUERY_FILE 
ACTION => RUN_QUERY_FILE
msf6 auxiliary(gather/ldap_query) > set QUERY_FILE_PATH /home/gwillcox/git/metasploit-framework/test.yaml
QUERY_FILE_PATH => /home/gwillcox/git/metasploit-framework/test.yaml
msf6 auxiliary(gather/ldap_query) > show options

Module options (auxiliary/gather/ldap_query):

   Name             Current Setting                     Required  Description
   ----             ---------------                     --------  -----------
   BASE_DN                                              no        LDAP base DN if you already have it
   BIND_DN          normal@daforest.com                 no        The username to authenticate to LDAP server
   BIND_PW          thePassword123                      no        Password for the BIND_DN
   OUTPUT_FORMAT    table                               yes       The output format to use (Accepted: csv, table, json)
   QUERY_FILE_PATH  /home/gwillcox/git/metasploit-fram  no        Path to the JSON or YAML file to load and run queries from
                    ework/test.yaml
   RHOSTS           172.27.51.83                        yes       The target host(s), see https://github.com/rapid7/metasploit-f
                                                                  ramework/wiki/Using-Metasploit
   RPORT            389                                 yes       The target port
   SSL              false                               no        Enable SSL on the LDAP connection


Auxiliary action:

   Name            Description
   ----            -----------
   RUN_QUERY_FILE  Execute a custom set of LDAP queries from the JSON or YAML file specified by QUERY_FILE.


msf6 auxiliary(gather/ldap_query) > run
[*] Running module against 172.27.51.83

[+] Successfully bound to the LDAP server!
[*] Discovering base DN automatically
[+] 172.27.51.83:389 Discovered base DN: DC=daforest,DC=com
[*] Loading queries from /home/gwillcox/git/metasploit-framework/test.yaml...
[*] Running ENUM_USERS...
[*] CN=Administrator CN=Users DC=daforest DC=com
============================================

 Name         Attributes
 ----         ----------
 description  Built-in account for administering the computer/domain
 name         Administrator

[*] CN=Guest CN=Users DC=daforest DC=com
====================================

 Name         Attributes
 ----         ----------
 description  Built-in account for guest access to the computer/domain
 name         Guest

*cut for brevity*

[*] Running ENUM_ORGUNITS...
[*] OU=Domain Controllers DC=daforest DC=com
========================================

 Name         Attributes
 ----         ----------
 description  Default container for domain controllers
 name         Domain Controllers

[*] OU=Admin DC=daforest DC=com
===========================

 Name  Attributes
 ----  ----------
 name  Admin

[*] OU=Tier 0 OU=Admin DC=daforest DC=com
=====================================

 Name  Attributes
 ----  ----------
 name  Tier 0

*cut for brevity*

[*] Running ENUM_GROUPS...
[*] CN=Administrators CN=Builtin DC=daforest DC=com
===============================================

 Name       Attributes
 ----       ----------
 grouptype  -2147483643
 name       Administrators

[*] CN=Users CN=Builtin DC=daforest DC=com
======================================

 Name       Attributes
 ----       ----------
 grouptype  -2147483643
 name       Users

[*] CN=Guests CN=Builtin DC=daforest DC=com
=======================================

 Name       Attributes
 ----       ----------
 grouptype  -2147483643
 name       Guests

[*] CN=Print Operators CN=Builtin DC=daforest DC=com
================================================

 Name       Attributes
 ----       ----------
 grouptype  -2147483643
 name       Print Operators

[*] CN=Backup Operators CN=Builtin DC=daforest DC=com
=================================================

 Name       Attributes
 ----       ----------
 grouptype  -2147483643
 name       Backup Operators
 
*cut for brevity*

[*] CN=EL-chu-distlist1 OU=T2-Roles OU=Tier 2 OU=Admin DC=daforest DC=com
=====================================================================

 Name       Attributes
 ----       ----------
 grouptype  -2147483646
 name       EL-chu-distlist1

[*] Auxiliary module execution completed
msf6 auxiliary(gather/ldap_query) > 
```

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
