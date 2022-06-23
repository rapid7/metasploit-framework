## Vulnerable Application
This module demonstrates setting up and running a basic LDAP server in Metasploit. The data it hosts is provided by the
`LDIF_FILE`.

## Verification Steps

1. Start msfconsole
1. Do: `use auxiliary/server/ldap`
1. Do: `set LDIF_FILE data/exploits/ldap/msf.ldif`
    * This assumes the working directory is the top-level Metasploit Framework directory and configures the module to
      use the included template.
1. Do: `run`
1. From a new shell, do: `ldapsearch -x -H ldap://192.168.159.128 -b "dc=metasploit,dc=com" "(objectClass=*)"`
    * This runs a query using the `ldapsearch` utility to show the server is responsive. 

## Options

### LDIF_FILE

Directory LDIF file path.

## Scenarios

### Metasploit Server Demonstration

```
msf6 > use auxiliary/server/ldap
msf6 auxiliary(server/ldap) > set LDIF_FILE data/exploits/ldap/msf.ldif
LDIF_FILE => data/exploits/ldap/msf.ldif
msf6 auxiliary(server/ldap) > show options 

Module options (auxiliary/server/ldap):

   Name       Current Setting              Required  Description
   ----       ---------------              --------  -----------
   LDIF_FILE  data/exploits/ldap/msf.ldif  no        Directory LDIF file path
   SRVHOST    0.0.0.0                      yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT    389                          yes       The local port to listen on.


Auxiliary action:

   Name     Description
   ----     -----------
   Service  Run LDAP server


msf6 auxiliary(server/ldap) > run
[*] Auxiliary module running as background job 0.
msf6 auxiliary(server/ldap) > 


```

From another shell:

```
$ ldapsearch -x -H ldap://192.168.159.128 -b "dc=metasploit,dc=com" "(objectClass=*)"
# extended LDIF
#
# LDAPv3
# base <dc=metasploit,dc=com> with scope subtree
# filter: (objectClass=*)
# requesting: ALL
#

# metasploit.com
dn: dc=metasploit,dc=com
objectClass: dcObject
objectClass: organization
o: Metasploit Framework
dc: metasploit

# search result
search: 2
result: 0 Success
text: Success

# numResponses: 2
# numEntries: 1

```
