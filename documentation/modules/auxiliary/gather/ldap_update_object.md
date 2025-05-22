## Description

The `ldap_update_object` module allows users to update attributes of LDAP objects in an Active Directory environment.
This module is flexible, enabling users to specify the target object and the attribute they wish to modify.

## Verification Steps

1. On the target host determine the current UPN value of the user you wish to update:
```powershell
PS C:\Users\Administrator> Get-ADUser -Identity user2 -Properties UserPrincipalName | Select-Object UserPrincipalName

UserPrincipalName
-----------------
user2
```
1. Start `msfconsole`
1. Do: `use auxiliary/gather/ldap_update_object`
1. Do: `set RHOST [IP]`
1. Do: `set LDAPDomain [DOMAIN]`
1. Do: `set LDAPUsername [USERNAME]`
1. Do: `set LDAPPassword [PASSWORD]`
1. Do: `set TARGET_USERNAME [TARGET_USERNAME]`
1. Do: `set ATTRIBUTE userPrincipalName`
1. Do: `set NEW_VALUE Administrator`
1. Do: `run`
1. Verify the attribute has been updated successfully:
```powershell
PS C:\Users\Administrator> Get-ADUser -Identity user2 -Properties UserPrincipalName | Select-Object UserPrincipalName

UserPrincipalName
-----------------
Administrator
```

## Options

### TARGET_USERNAME
The username of the target LDAP object whose attribute you want to update. This is used to locate the specific object in the LDAP directory.

### ATTRIBUTE
The LDAP attribute to update. For example, `userPrincipalName` can be used to update the User Principal Name of the target object.

### NEW_VALUE
The new value to assign to the specified attribute. For example, if updating the `userPrincipalName`, this would be the new UPN value, which might be `Administrator`

## Scenarios
### Update the userPrincipalName of user2 from "user2" to "Administrator" using user1's credentials (who has Write privileges over user2).

```
msf6 auxiliary(gather/ldap_update_object) > set attribute userPrincipalName
attribute => userPrincipalName
msf6 auxiliary(gather/ldap_update_object) > set ldapdomain kerberos.issue
ldapdomain => kerberos.issue     
msf6 auxiliary(gather/ldap_update_object) > set ldappassword N0tpassword!
ldappassword => N0tpassword!
msf6 auxiliary(gather/ldap_update_object) > set ldapusername user1
ldapusername => user1
msf6 auxiliary(gather/ldap_update_object) > set new_value Administrator
new_value => Administrator
msf6 auxiliary(gather/ldap_update_object) > set rhosts 172.16.199.200
rhosts => 172.16.199.200
msf6 auxiliary(gather/ldap_update_object) > set target_username user2
target_username => user2
msf6 auxiliary(gather/ldap_update_object) > run
[*] Running module against 172.16.199.200
[*] Connecting to LDAP on 172.16.199.200:389...
[*] Searching for DN of target user user2...
[+] Found target user DN: CN=user2,CN=Users,DC=kerberos,DC=issue
[*] Attempting to update userPrincipalName for CN=user2,CN=Users,DC=kerberos,DC=issue to Administrator...
[+] Successfully updated CN=user2,CN=Users,DC=kerberos,DC=issue's userPrincipalName to Administrator
[*] Auxiliary module execution completed
```

## Notes

- Ensure the user account used for authentication has sufficient privileges to modify the specified attribute.
- Use caution when modifying LDAP attributes, as incorrect changes can disrupt directory services.
