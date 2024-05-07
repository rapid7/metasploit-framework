## Vulnerable Application
This module allows users to query an LDAP server using either a custom LDAP query, or
a set of LDAP queries under a specific category. Users can also specify a JSON or YAML
file containing custom queries to be executed using the `RUN_QUERY_FILE` action.
If this action is specified, then `QUERY_FILE_PATH` must be a path to the location
of this JSON/YAML file on disk.

Users can also run a single query by using the `RUN_SINGLE_QUERY` option and then setting
the `QUERY_FILTER` datastore option to the filter to send to the LDAP server and `QUERY_ATTRIBUTES`
to a comma separated string containing the list of attributes they are interested in obtaining
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
                                                                                                                                                                                              Name             Current Setting      Required  Description
   ----           ---------------      --------  -----------
   BASE_DN                             no        LDAP base DN if you already have it
   DOMAIN                              no        The domain to authenticate to
   OUTPUT_FORMAT  table                yes       The output format to use (Accepted: csv, table, json)
   PASSWORD       thePassword123       no        The password to authenticate with
   RHOSTS         172.27.51.83         yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT          389                  yes       The target port
   SSL            false                no        Enable SSL on the LDAP connection
   USERNAME       normal@daforest.com  no        The username to authenticate with


   When ACTION is RUN_QUERY_FILE:

   Name             Current Setting                                    Required  Description
   ----             ---------------                                    --------  -----------
   QUERY_FILE_PATH  /home/gwillcox/git/metasploit-framework/test.yaml  no        Path to the JSON or YAML file to load and run queries from


   When ACTION is RUN_SINGLE_QUERY:

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   QUERY_ATTRIBUTES                   no        Comma separated list of attributes to retrieve from the server
   QUERY_FILTER                       no        Filter to send to the target LDAP server to perform the query

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
msf6 > use auxiliary/gather/ldap_query 
msf6 auxiliary(gather/ldap_query) > set RHOSTS 192.168.159.10
RHOSTS => 192.168.159.10
msf6 auxiliary(gather/ldap_query) > set USERNAME aliddle
USERNAME => aliddle
msf6 auxiliary(gather/ldap_query) > set PASSWORD Password1!
PASSWORD => Password1!
msf6 auxiliary(gather/ldap_query) > set DOMAIN msflab.local
DOMAIN => msflab.local
msf6 auxiliary(gather/ldap_query) > enum_computers output_format=table
[*] Running module against 192.168.159.10

[*] Discovering base DN automatically
[+] 192.168.159.10:389 Discovered base DN: DC=msflab,DC=local
[+] 192.168.159.10:389 Discovered schema DN: DC=msflab,DC=local
CN=DC OU=Domain Controllers DC=msflab DC=local
==============================================

 Name                    Attributes
 ----                    ----------
 distinguishedname       CN=DC,OU=Domain Controllers,DC=msflab,DC=local
 dnshostname             DC.msflab.local
 lastlogontimestamp      2023-01-30 13:46:10 UTC
 name                    DC
 objectsid               S-1-5-21-3402587289-1488798532-3618296993-1001
 operatingsystem         Windows Server 2019 Standard
 operatingsystemversion  10.0 (17763)
 primarygroupid          516
 samaccountname          DC$
 serviceprincipalname    Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/DC.msflab.local || ldap/DC.msflab.local/ForestDnsZones.msflab.local || ldap/DC.msflab.local/DomainDnsZones.msflab.local || TERMSRV/DC || TERMSRV/DC.msflab.local || DNS/D
                         C.msflab.local || GC/DC.msflab.local/msflab.local || RestrictedKrbHost/DC.msflab.local || RestrictedKrbHost/DC || RPC/741f826d-2ac1-44c4-a07e-f717b0f6eaf6._msdcs.msflab.local || HOST/DC/MSFLAB || HOST/DC.msflab.
                         local/MSFLAB || HOST/DC || HOST/DC.msflab.local || HOST/DC.msflab.local/msflab.local || E3514235-4B06-11D1-AB04-00C04FC2DCD2/741f826d-2ac1-44c4-a07e-f717b0f6eaf6/msflab.local || ldap/DC/MSFLAB || ldap/741f826d-2
                         ac1-44c4-a07e-f717b0f6eaf6._msdcs.msflab.local || ldap/DC.msflab.local/MSFLAB || ldap/DC || ldap/DC.msflab.local || ldap/DC.msflab.local/msflab.local

CN=DESKTOP-24B2FAJP CN=Computers DC=msflab DC=local
===================================================

 Name                Attributes
 ----                ----------
 distinguishedname   CN=DESKTOP-24B2FAJP,CN=Computers,DC=msflab,DC=local
 lastlogontimestamp  2023-01-18 00:28:30 UTC
 name                DESKTOP-24B2FAJP
 objectsid           S-1-5-21-3402587289-1488798532-3618296993-1603
 primarygroupid      515
 samaccountname      DESKTOP-24B2FAJP$

CN=DESKTOP-CXXIBPAE CN=Computers DC=msflab DC=local
===================================================

 Name                Attributes
 ----                ----------
 distinguishedname   CN=DESKTOP-CXXIBPAE,CN=Computers,DC=msflab,DC=local
 lastlogontimestamp  2023-01-18 14:08:29 UTC
 name                DESKTOP-CXXIBPAE
 objectsid           S-1-5-21-3402587289-1488798532-3618296993-1604
 primarygroupid      515
 samaccountname      DESKTOP-CXXIBPAE$

CN=DESKTOP-MO5E49K8 CN=Computers DC=msflab DC=local
===================================================

 Name                Attributes
 ----                ----------
 distinguishedname   CN=DESKTOP-MO5E49K8,CN=Computers,DC=msflab,DC=local
 lastlogontimestamp  2023-01-18 14:09:58 UTC
 name                DESKTOP-MO5E49K8
 objectsid           S-1-5-21-3402587289-1488798532-3618296993-1605
 primarygroupid      515
 samaccountname      DESKTOP-MO5E49K8$

[*] Auxiliary module execution completed
msf6 auxiliary(gather/ldap_query) >
```

### ENUM_COMPUTERS with CSV Output
```
msf6 > use auxiliary/gather/ldap_query 
msf6 auxiliary(gather/ldap_query) > set RHOSTS 192.168.159.10
RHOSTS => 192.168.159.10
msf6 auxiliary(gather/ldap_query) > set USERNAME aliddle
USERNAME => aliddle
msf6 auxiliary(gather/ldap_query) > set PASSWORD Password1!
PASSWORD => Password1!
msf6 auxiliary(gather/ldap_query) > set DOMAIN msflab.local
DOMAIN => msflab.local
msf6 auxiliary(gather/ldap_query) > enum_computers output_format=csv
[*] Running module against 192.168.159.10

[*] Discovering base DN automatically
[+] 192.168.159.10:389 Discovered base DN: DC=msflab,DC=local
[+] 192.168.159.10:389 Discovered schema DN: DC=msflab,DC=local
Name,Attributes
"dn","CN=DC,OU=Domain Controllers,DC=msflab,DC=local"
"distinguishedname","CN=DC,OU=Domain Controllers,DC=msflab,DC=local"
"name","DC"
"primarygroupid","516"
"objectsid","S-1-5-21-3402587289-1488798532-3618296993-1001"
"samaccountname","DC$"
"operatingsystem","Windows Server 2019 Standard"
"operatingsystemversion","10.0 (17763)"
"dnshostname","DC.msflab.local"
"serviceprincipalname","Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/DC.msflab.local || ldap/DC.msflab.local/ForestDnsZones.msflab.local || ldap/DC.msflab.local/DomainDnsZones.msflab.local || TERMSRV/DC || TERMSRV/DC.msflab.local || DNS/DC.msflab.local || GC/DC.msflab.local/msflab.local || RestrictedKrbHost/DC.msflab.local || RestrictedKrbHost/DC || RPC/741f826d-2ac1-44c4-a07e-f717b0f6eaf6._msdcs.msflab.local || HOST/DC/MSFLAB || HOST/DC.msflab.local/MSFLAB || HOST/DC || HOST/DC.msflab.local || HOST/DC.msflab.local/msflab.local || E3514235-4B06-11D1-AB04-00C04FC2DCD2/741f826d-2ac1-44c4-a07e-f717b0f6eaf6/msflab.local || ldap/DC/MSFLAB || ldap/741f826d-2ac1-44c4-a07e-f717b0f6eaf6._msdcs.msflab.local || ldap/DC.msflab.local/MSFLAB || ldap/DC || ldap/DC.msflab.local || ldap/DC.msflab.local/msflab.local"
"lastlogontimestamp","2023-01-30 13:46:10 UTC"

Name,Attributes
"dn","CN=DESKTOP-24B2FAJP,CN=Computers,DC=msflab,DC=local"
"distinguishedname","CN=DESKTOP-24B2FAJP,CN=Computers,DC=msflab,DC=local"
"name","DESKTOP-24B2FAJP"
"primarygroupid","515"
"objectsid","S-1-5-21-3402587289-1488798532-3618296993-1603"
"samaccountname","DESKTOP-24B2FAJP$"
"lastlogontimestamp","2023-01-18 00:28:30 UTC"

Name,Attributes
"dn","CN=DESKTOP-CXXIBPAE,CN=Computers,DC=msflab,DC=local"
"distinguishedname","CN=DESKTOP-CXXIBPAE,CN=Computers,DC=msflab,DC=local"
"name","DESKTOP-CXXIBPAE"
"primarygroupid","515"
"objectsid","S-1-5-21-3402587289-1488798532-3618296993-1604"
"samaccountname","DESKTOP-CXXIBPAE$"
"lastlogontimestamp","2023-01-18 14:08:29 UTC"

Name,Attributes
"dn","CN=DESKTOP-MO5E49K8,CN=Computers,DC=msflab,DC=local"
"distinguishedname","CN=DESKTOP-MO5E49K8,CN=Computers,DC=msflab,DC=local"
"name","DESKTOP-MO5E49K8"
"primarygroupid","515"
"objectsid","S-1-5-21-3402587289-1488798532-3618296993-1605"
"samaccountname","DESKTOP-MO5E49K8$"
"lastlogontimestamp","2023-01-18 14:09:58 UTC"

[*] Auxiliary module execution completed
msf6 auxiliary(gather/ldap_query) >
```

### ENUM_COMPUTERS with JSON Output
```
msf6 > use auxiliary/gather/ldap_query 
msf6 auxiliary(gather/ldap_query) > set RHOSTS 192.168.159.10
RHOSTS => 192.168.159.10
msf6 auxiliary(gather/ldap_query) > set USERNAME aliddle
USERNAME => aliddle
msf6 auxiliary(gather/ldap_query) > set PASSWORD Password1!
PASSWORD => Password1!
msf6 auxiliary(gather/ldap_query) > set DOMAIN msflab.local
DOMAIN => msflab.local
msf6 auxiliary(gather/ldap_query) > enum_computers output_format=json
[*] Running module against 192.168.159.10

[*] Discovering base DN automatically
[+] 192.168.159.10:389 Discovered base DN: DC=msflab,DC=local
[+] 192.168.159.10:389 Discovered schema DN: DC=msflab,DC=local
[*] CN=DC OU=Domain Controllers DC=msflab DC=local
{
  "dn": "CN=DC,OU=Domain Controllers,DC=msflab,DC=local",
  "distinguishedname": "CN=DC,OU=Domain Controllers,DC=msflab,DC=local",
  "name": "DC",
  "primarygroupid": "516",
  "objectsid": "S-1-5-21-3402587289-1488798532-3618296993-1001",
  "samaccountname": "DC$",
  "operatingsystem": "Windows Server 2019 Standard",
  "operatingsystemversion": "10.0 (17763)",
  "dnshostname": "DC.msflab.local",
  "serviceprincipalname": "Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/DC.msflab.local || ldap/DC.msflab.local/ForestDnsZones.msflab.local || ldap/DC.msflab.local/DomainDnsZones.msflab.local || TERMSRV/DC || TERMSRV/DC.msflab.local || DNS/DC.msflab.local || GC/DC.msflab.local/msflab.local || RestrictedKrbHost/DC.msflab.local || RestrictedKrbHost/DC || RPC/741f826d-2ac1-44c4-a07e-f717b0f6eaf6._msdcs.msflab.local || HOST/DC/MSFLAB || HOST/DC.msflab.local/MSFLAB || HOST/DC || HOST/DC.msflab.local || HOST/DC.msflab.local/msflab.local || E3514235-4B06-11D1-AB04-00C04FC2DCD2/741f826d-2ac1-44c4-a07e-f717b0f6eaf6/msflab.local || ldap/DC/MSFLAB || ldap/741f826d-2ac1-44c4-a07e-f717b0f6eaf6._msdcs.msflab.local || ldap/DC.msflab.local/MSFLAB || ldap/DC || ldap/DC.msflab.local || ldap/DC.msflab.local/msflab.local",
  "lastlogontimestamp": "2023-01-30 13:46:10 UTC"
}
[*] CN=DESKTOP-24B2FAJP CN=Computers DC=msflab DC=local
{
  "dn": "CN=DESKTOP-24B2FAJP,CN=Computers,DC=msflab,DC=local",
  "distinguishedname": "CN=DESKTOP-24B2FAJP,CN=Computers,DC=msflab,DC=local",
  "name": "DESKTOP-24B2FAJP",
  "primarygroupid": "515",
  "objectsid": "S-1-5-21-3402587289-1488798532-3618296993-1603",
  "samaccountname": "DESKTOP-24B2FAJP$",
  "lastlogontimestamp": "2023-01-18 00:28:30 UTC"
}
[*] CN=DESKTOP-CXXIBPAE CN=Computers DC=msflab DC=local
{
  "dn": "CN=DESKTOP-CXXIBPAE,CN=Computers,DC=msflab,DC=local",
  "distinguishedname": "CN=DESKTOP-CXXIBPAE,CN=Computers,DC=msflab,DC=local",
  "name": "DESKTOP-CXXIBPAE",
  "primarygroupid": "515",
  "objectsid": "S-1-5-21-3402587289-1488798532-3618296993-1604",
  "samaccountname": "DESKTOP-CXXIBPAE$",
  "lastlogontimestamp": "2023-01-18 14:08:29 UTC"
}
[*] CN=DESKTOP-MO5E49K8 CN=Computers DC=msflab DC=local
{
  "dn": "CN=DESKTOP-MO5E49K8,CN=Computers,DC=msflab,DC=local",
  "distinguishedname": "CN=DESKTOP-MO5E49K8,CN=Computers,DC=msflab,DC=local",
  "name": "DESKTOP-MO5E49K8",
  "primarygroupid": "515",
  "objectsid": "S-1-5-21-3402587289-1488798532-3618296993-1605",
  "samaccountname": "DESKTOP-MO5E49K8$",
  "lastlogontimestamp": "2023-01-18 14:09:58 UTC"
}
[*] Auxiliary module execution completed
msf6 auxiliary(gather/ldap_query) > 
```
