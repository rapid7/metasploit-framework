## LDAP Workflows

Lightweight Directory Access Protocol (LDAP) is a method for obtaining distributed directory information from a service.
For Windows Active Directory environments this is a useful method of enumerating users, computers, misconfigurations, etc.

LDAP on Windows environments are found on:

- 389/TCP - LDAP
- 636/TCP - LDAPS
- 3268 - Global Catalog LDAP
- 3269 - Global Catalog LDAPS

### Lab Environment

LDAP support is enabled by default on a Windows environment when you install Active Directory.
For LDAPS support to be enabled on port 636, you will have to configure [[AD CS (Active Directory Certificate Services)|ad-certificates/overview.md]]

### Authentication

The LDAP module supports the following forms of authentication with the `LDAP::Auth` option:

- auto
- ntlm
- kerberos - Example below
- plaintext
- none

### LDAP Enumeration

The `auxiliary/gather/ldap_query.rb` module can be used for querying LDAP:

```
use auxiliary/gather/ldap_query
run rhost=192.168.123.13 username=Administrator@domain.local password=p4$$w0rd action=ENUM_ACCOUNTS
```

Example output:

```msf
msf6 auxiliary(gather/ldap_query) > run rhost=192.168.123.13 username=Administrator@domain.local password=p4$$w0rd action=ENUM_ACCOUNTS
[*] Running module against 192.168.123.13

[*] Discovering base DN automatically
[+] 192.168.123.13:389 Discovered base DN: DC=domain,DC=local
CN=Administrator CN=Users DC=domain DC=local
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

This module has a selection of inbuilt queries which can be configured via the `action` setting to make enumeration easier:

- `ENUM_ACCOUNTS` - Dump info about all known user accounts in the domain.
- `ENUM_AD_CS_CAS` - Enumerate AD CS certificate authorities.
- `ENUM_AD_CS_CERT_TEMPLATES` - Enumerate AD CS certificate templates.
- `ENUM_ADMIN_OBJECTS` - Dump info about all objects with protected ACLs (i.e highly privileged objects).
- `ENUM_ALL_OBJECT_CATEGORY` - Dump all objects containing any objectCategory field.
- `ENUM_ALL_OBJECT_CLASS` - Dump all objects containing any objectClass field.
- `ENUM_COMPUTERS` - Dump all objects containing an objectCategory or objectClass of Computer.
- `ENUM_CONSTRAINED_DELEGATION` - Dump info about all known objects that allow constrained delegation.
- `ENUM_DNS_RECORDS` - Dump info about DNS records the server knows about using the dnsNode object class.
- `ENUM_DNS_ZONES` - Dump info about DNS zones the server knows about using the dnsZone object class under the DC DomainDnsZones. This isneeded - as without this BASEDN prefix we often miss certain entries.
- `ENUM_DOMAIN` - Dump info about the Active Directory domain.
- `ENUM_DOMAIN_CONTROLLERS` - Dump all known domain controllers.
- `ENUM_EXCHANGE_RECIPIENTS` - Dump info about all known Exchange recipients.
- `ENUM_EXCHANGE_SERVERS` - Dump info about all known Exchange servers.
- `ENUM_GMSA_HASHES` - Dump info about GMSAs and their password hashes if available.
- `ENUM_GROUPS` - Dump info about all known groups in the LDAP environment.
- `ENUM_GROUP_POLICY_OBJECTS` - Dump info about all known Group Policy Objects (GPOs) in the LDAP environment.
- `ENUM_HOSTNAMES` - Dump info about all known hostnames in the LDAP environment.
- `ENUM_LAPS_PASSWORDS` - Dump info about computers that have LAPS enabled, and passwords for them if available.
- `ENUM_LDAP_SERVER_METADATA` - Dump metadata about the setup of the domain.
- `ENUM_MACHINE_ACCOUNT_QUOTA` - Dump the number of computer accounts a user is allowed to create in a domain.
- `ENUM_ORGROLES` - Dump info about all known organization roles in the LDAP environment.
- `ENUM_ORGUNITS` - Dump info about all known organizational units in the LDAP environment.
- `ENUM_UNCONSTRAINED_DELEGATION` - Dump info about all known objects that allow unconstrained delegation.
- `ENUM_USER_ACCOUNT_DISABLED` - Dump info about disabled user accounts.
- `ENUM_USER_ACCOUNT_LOCKED_OUT` - Dump info about locked out user accounts.
- `ENUM_USER_ASREP_ROASTABLE` - Dump info about all users who are configured not to require kerberos pre-authentication and are therefore AS-REP roastable.
- `ENUM_USER_PASSWORD_NEVER_EXPIRES` - Dump info about all users whose password never expires.
- `ENUM_USER_PASSWORD_NOT_REQUIRED` - Dump info about all users whose password never expires and whose account is still enabled.
- `ENUM_USER_SPNS_KERBEROAST` - Dump info about all user objects with Service Principal Names (SPNs) for kerberoasting.

### Kerberos Authentication

Details on the Kerberos specific option names are documented in [[Kerberos Service Authentication|kerberos/service_authentication]]

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
[+] 192.168.123.13:389 Discovered base DN: DC=domain,DC=local
CN=Administrator CN=Users DC=domain DC=local
============================================

 Name                Attributes
 ----                ----------
 badpwdcount         0
 pwdlastset          133184302034979121
 samaccountname      Administrator
 useraccountcontrol  512
 ... etc ...
```
