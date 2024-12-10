## Vulnerable Application
Add, lookup and delete user / machine accounts via MS-SAMR. By default standard active directory users can add up to 10
new computers to the domain (MachineAccountQuota). Administrative privileges however are required to delete the created
accounts, or to create/delete user accounts.

## Verification Steps

1. From msfconsole
2. Do: `use auxiliary/admin/dcerpc/samr_account`
3. Set the `RHOSTS`, `SMBUser` and `SMBPass` options
   1. Set the `ACCOUNT_NAME` option for `DELETE_ACCOUNT` and `LOOKUP_ACCOUNT` actions
4. Run the module and see that a new machine account was added

## Options

### SMBDomain

The Windows domain to use for authentication. The domain will automatically be identified if this option is left in its
default value.

### ACCOUNT_NAME

The account name to add, lookup or delete. This option is optional for the `ADD_COMPUTER` action, and required for the
`ADD_USER`, `LOOKUP_ACCOUNT` and `DELETE_ACCOUNT` actions. If left blank for `ADD_COMPUTER`, a random, realistic name
will be generated.

### ACCOUNT_PASSWORD

The password for the new account. This option is only used for the `ADD_COMPUTER` and `ADD_USER` actions. If left 
blank, a random value will be generated.

## Actions

### ADD_COMPUTER

Add a new computer to the domain. This action will fail with status `STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED` if the
user has exceeded the maximum number of computer accounts that they are allowed to create.

After the computer account is created, the password will be set for it. If `ACCOUNT_NAME` is set, that value will be
used and the module will fail if the specified name is already in use. If `ACCOUNT_NAME` is *not* set, a random value
will be used.

### ADD_USER

Add a new user to the domain. The account being used to create the new user must have permission to do so. 

After the user account is created, the password will be set for it. The `ACCOUNT_NAME` option must be set to the name of
the account to create. The module will fail if the specified name is already in use.

### DELETE_ACCOUNT

Delete a user or computer account from the domain. This action requires that the `ACCOUNT_NAME` option be set.

### LOOKUP_ACCOUNT

Lookup a user or computer account in the domain. This action verifies that the specified account exists, and looks up
its security ID (SID), which includes the relative ID (RID) as the last component.

## Scenarios

### Windows Server 2019

First, a new computer account is created and its details are logged to the database.

```
msf6 auxiliary(admin/dcerpc/samr_account) > set RHOSTS 192.168.159.96
RHOSTS => 192.168.159.96
msf6 auxiliary(admin/dcerpc/samr_account) > set SMBUser aliddle
SMBUser => aliddle
msf6 auxiliary(admin/dcerpc/samr_account) > set SMBPass Password1
SMBPass => Password1
msf6 auxiliary(admin/dcerpc/samr_account) > show options

Module options (auxiliary/admin/dcerpc/samr_account):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   ACCOUNT _NAME                      no        The computer name
   ACCOUNT_PASSWORD                   no        The password for the new computer
   RHOSTS            192.168.159.96   yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT             445              yes       The target port (TCP)
   SMBDomain         .                no        The Windows domain to use for authentication
   SMBPass           Password1        no        The password for the specified username
   SMBUser           aliddle          no        The username to authenticate as


Auxiliary action:

   Name          Description
   ----          -----------
   ADD_COMPUTER  Add a computer account


msf6 auxiliary(admin/dcerpc/samr_account) > run
[*] Running module against 192.168.159.96

[*] 192.168.159.96:445 - Using automatically identified domain: MSFLAB
[+] 192.168.159.96:445 - Successfully created MSFLAB\DESKTOP-2X8F54QG$ with password MCoDkNALd3SdGR1GoLhqniEkWa8Me9FY
[*] Auxiliary module execution completed
msf6 auxiliary(admin/dcerpc/samr_account) > creds
Credentials
===========

host            origin          service        public             private                           realm   private_type  JtR Format
----            ------          -------        ------             -------                           -----   ------------  ----------
192.168.159.96  192.168.159.96  445/tcp (smb)  DESKTOP-2X8F54QG$  MCoDkNALd3SdGR1GoLhqniEkWa8Me9FY  MSFLAB  Password

msf6 auxiliary(admin/dcerpc/samr_account) >
```
