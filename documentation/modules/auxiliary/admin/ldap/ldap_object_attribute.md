## Description

The `ldap_object_attribute` module allows users to read, create, update or delete attributes of LDAP objects in an Active Directory environment.
This module is flexible, enabling users to specify the target object and the attribute they wish to interact with.

## Verification Steps

### Action Update
1. On the target host determine the current UPN value of the user you wish to update:
```powershell
PS C:\Users\Administrator> Get-ADUser -Identity user2 -Properties UserPrincipalName | Select-Object UserPrincipalName

UserPrincipalName
-----------------
user2
```
1. Start `msfconsole`
1. Do: `use auxiliary/gather/ldap_object_attribute`
1. Do: `set RHOST [IP]`
1. Do: `set LDAPDomain [DOMAIN]`
1. Do: `set LDAPUsername [USERNAME]`
1. Do: `set LDAPPassword [PASSWORD]`
1. Do: `set TARGET_USERNAME [TARGET_USERNAME]`
1. Do: `set ATTRIBUTE userPrincipalName`
1. Do: `set OBJECT_LOOKUP sAMAccountName`
1. Do: `set OBJECT [User you wish to update]`
1. Do: `set VALUE [New value for the attribute (e.g., Administrator)]`
1. Do: `set ACTION update`
1. Do: `run`
1. Verify the attribute has been updated successfully:
```powershell
PS C:\Users\Administrator> Get-ADUser -Identity user2 -Properties UserPrincipalName | Select-Object UserPrincipalName

UserPrincipalName
-----------------
Administrator
```

## Options

### OBJECT
The username of the target LDAP object whose attribute you want to update. This is used to locate the specific object in the LDAP directory.

### OBJECT_LOOKUP
How to look up the target LDAP object. This can either be done by specifying a DN or by specifying `sAMAaccountName` in order to work with AD account attributes. 

### ATTRIBUTE
The LDAP attribute to update. For example, `userPrincipalName` can be used to update the User Principal Name of the target object.

### VALUE
Required when running "Update" or "Create" actions and is the value of the specified attribute that you want to set for the target object.

## Scenarios
### Action `Update`

```
msf6 auxiliary(gather/ldap_object_attribute) > set action update
action => update
msf6 auxiliary(gather/ldap_object_attribute) > set rhost 172.16.199.200
rhost => 172.16.199.200
msf6 auxiliary(gather/ldap_object_attribute) > set LDAPDomain kerberos.issue
LDAPDomain => kerberos.issue
msf6 auxiliary(gather/ldap_object_attribute) > set LDAPUsername user1
LDAPUsername => user1
msf6 auxiliary(gather/ldap_object_attribute) > set LDAPPassword N0tpassword!
LDAPPassword => N0tpassword!
msf6 auxiliary(gather/ldap_object_attribute) > set OBJECT user2
OBJECT => user2
msf6 auxiliary(gather/ldap_object_attribute) > set OBJECT_LOOKUP sAMAccountName
OBJECT_LOOKUP => sAMAccountName
msf6 auxiliary(gather/ldap_object_attribute) > set ATTRIBUTE userPrincipalName
ATTRIBUTE => userPrincipalName
msf6 auxiliary(gather/ldap_object_attribute) > set VALUE Administrator
VALUE => Administrator
msf6 auxiliary(gather/ldap_object_attribute) > run
[*] Running module against 172.16.199.200
[*] Discovering base DN automatically
[*] Original value of user2's userPrincipalName:
[*] Attempting to update userPrincipalName for CN=user2,CN=Users,DC=kerberos,DC=issue to Administrator...
[+] Successfully updated CN=user2,CN=Users,DC=kerberos,DC=issue's userPrincipalName to Administrator
[+] The operation completed successfully!
[*] Auxiliary module execution completed
```

### Action `Read`
```
msf6 auxiliary(gather/ldap_object_attribute) > set action read
action => read
msf6 auxiliary(gather/ldap_object_attribute) > set rhost 172.16.199.200
rhost => 172.16.199.200
msf6 auxiliary(gather/ldap_object_attribute) > set LDAPDomain kerberos.issue
LDAPDomain => kerberos.issue
msf6 auxiliary(gather/ldap_object_attribute) > set LDAPUsername user1
LDAPUsername => user1
msf6 auxiliary(gather/ldap_object_attribute) > set LDAPPassword N0tpassword!
LDAPPassword => N0tpassword!
msf6 auxiliary(gather/ldap_object_attribute) > set OBJECT user2
OBJECT => user2
msf6 auxiliary(gather/ldap_object_attribute) > set OBJECT_LOOKUP sAMAccountName
OBJECT_LOOKUP => sAMAccountName
msf6 auxiliary(gather/ldap_object_attribute) > set ATTRIBUTE userPrincipalName
ATTRIBUTE => userPrincipalName
msf6 auxiliary(gather/ldap_object_attribute) > run
[*] Running module against 172.16.199.200
[*] Discovering base DN automatically
[+] Found CN=user2,CN=Users,DC=kerberos,DC=issue with userPrincipalName set to Administrator
[+] The operation completed successfully!
[*] Auxiliary module execution completed
```

### Action `Delete`
```
msf6 auxiliary(gather/ldap_object_attribute) > set action delete
action => delete
msf6 auxiliary(gather/ldap_object_attribute) > set rhost 172.16.199.200
rhost => 172.16.199.200
msf6 auxiliary(gather/ldap_object_attribute) > set LDAPDomain kerberos.issue
LDAPDomain => kerberos.issue
msf6 auxiliary(gather/ldap_object_attribute) > set LDAPUsername user1
LDAPUsername => user1
msf6 auxiliary(gather/ldap_object_attribute) > set LDAPPassword N0tpassword!
LDAPPassword => N0tpassword!
msf6 auxiliary(gather/ldap_object_attribute) > set OBJECT user2
OBJECT => user2
msf6 auxiliary(gather/ldap_object_attribute) > set OBJECT_LOOKUP sAMAccountName
OBJECT_LOOKUP => sAMAccountName
msf6 auxiliary(gather/ldap_object_attribute) > set ATTRIBUTE userPrincipalName
ATTRIBUTE => userPrincipalName
msf6 auxiliary(gather/ldap_object_attribute) > run
[*] Running module against 172.16.199.200
[*] Discovering base DN automatically
[*] Attempting to delete attribute userPrincipalName from CN=user2,CN=Users,DC=kerberos,DC=issue...
[+] Successfully deleted attribute userPrincipalName from CN=user2,CN=Users,DC=kerberos,DC=issue
[+] The operation completed successfully!
[*] Auxiliary module execution completed
```

### Action `Create` 
```
msf6 auxiliary(gather/ldap_object_attribute) > set action create
action => create
msf6 auxiliary(gather/ldap_object_attribute) > set rhost 172.16.199.200
rhost => 172.16.199.200
msf6 auxiliary(gather/ldap_object_attribute) > set LDAPDomain kerberos.issue
LDAPDomain => kerberos.issue
msf6 auxiliary(gather/ldap_object_attribute) > set LDAPUsername user1
LDAPUsername => user1
msf6 auxiliary(gather/ldap_object_attribute) > set LDAPPassword N0tpassword!
LDAPPassword => N0tpassword!
msf6 auxiliary(gather/ldap_object_attribute) > set OBJECT user2
OBJECT => user2
msf6 auxiliary(gather/ldap_object_attribute) > set OBJECT_LOOKUP sAMAccountName
OBJECT_LOOKUP => sAMAccountName
msf6 auxiliary(gather/ldap_object_attribute) > set ATTRIBUTE userPrincipalName
ATTRIBUTE => userPrincipalName
msf6 auxiliary(gather/ldap_object_attribute) > set VALUE Administrator
VALUE => Administrator
msf6 auxiliary(gather/ldap_object_attribute) > run
[*] Reloading module...
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST
[*] Running module against 172.16.199.200
[*] Discovering base DN automatically
[*] Attempting to add attribute userPrincipalName with value asdfasdf to CN=user2,CN=Users,DC=kerberos,DC=issue...
[+] Successfully added attribute userPrincipalName with value asdfasdf to CN=user2,CN=Users,DC=kerberos,DC=issue
[+] The operation completed successfully!
[*] Auxiliary module execution completed
```

## Notes

- Ensure the user account used for authentication has sufficient privileges to modify the specified attribute.
- Use caution when modifying LDAP attributes, as incorrect changes can disrupt directory services.
