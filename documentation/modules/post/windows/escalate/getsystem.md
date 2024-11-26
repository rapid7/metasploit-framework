## Vulnerable Application
This module uses the `getsystem` command to escalate the current session to the SYSTEM account using various techniques.

## Verification Steps

1. Do: `use post/windows/escalate/getsystem`
2. Do: `set SESSION -1`
3. Do: `run`

## Options

### TECHNIQUE
Specify a particular technique to use (1-6), otherwise try them all.

## Techniques
To be a getsystem technique instead of a local exploit, the technique should meet the following criteria:

* The technique must grant `NT AUTHORITY\SYSTEM`-level privileges through some means
* The technique must not have a patch either now or anticipated in the future (i.e. it is not a zero-day)
* The technique must escalate the current process in place and not execute a new payload
* The technique must not require any user-provided configuration options such as paths, ports, or credentials
* The technique must be highly reliable and avoid crashing the existing session
* The technique should work on both 32-bit and 64-bit architectures
* The technique should affect multiple versions of Windows

### 0 - All Techniques
The 0 technique will try all techniques, in order, starting at #1 and incrementing until one works.

### 1 - Named Pipe Impersonation
**Side Effects:** Creates a Service
**Requirements:** Group: Local Administrators
**Versions:** Windows XP / Server 2003 and later

This technique is classic named pipe impersonation where by a named pipe is opened on the target and a new service is
created to connect to it. When started, the service's configured command opens the named pipe as `NT AUTHORITY\SYSTEM`
which allows the listening process (Meterpreter) to obtain those privileges by calling [ImpersonateNamedPipeClient][1].

### 2 - Named Pipe Impersonation (DLL Dropper Variant)
**Side Effects:** Creates a Service, Writes to Disk
**Requirements:** Group: Local Administrators
**Versions:** Windows XP / Server 2003 and later

This technique is identical to technique #1, but writes a DLL to disk and configures the new service to execute it with
`rundll32` instead of using a command. When the service is started, `rundll32` will load the DLL which will connect to
the named pipe, allowing it to be impersonated. The DLL is deleted from disk once the operation is complete.

### 3 - Token Duplication
**Side Effects:** Injects into Processes
**Requirements:** Privilege: SeDebugPrivilege
**Versions:** Windows XP / Server 2003 and later

This technique will enable the `SeDebugPrivilege` privilege then enumerate and iterate over all running services. For each
running service, Meterpreter will attempt to open the process and reflectively inject a DLL into it. The DLL, once
injected and running in the context of the service process will check if it is currently running as
`NT AUTHORITY\SYSTEM` and if so, duplicate it's token to that of the Meterpreter process.

### 4 - Named Pipe Impersonation (RPCSS Variant)
**Side Effects:** None
**Requirements:** User: `NT AUTHORITY\NETWORK SERVICE`
**Versions:** Windows 8.1 / Server 2012 R2 and later

This technique will open a named pipe on the target, connects to and then impersonates itself. Due to how LSASS
functions if the Meterpreter process is running as `NT AUTHORITY\NETWORK SERVICE`, this can yield the necessary
privileges to open the RPCSS process which itself contains handles to `NT AUTHORITY\SYSTEM` tokens. Using the access to
the RPCSS process, one of these tokens is selected and duplicated.

#### References

* https://github.com/sailay1996/RpcSsImpersonator
* https://www.tiraniddo.dev/2020/04/sharing-logon-session-little-too-much.html
* https://windows-internals.com/faxing-your-way-to-system/

### 5 - Named Pipe Impersonation (Print Spooler Variant)
**Side Effects:** None
**Requirements:** Privilege: SeImpersonatePrivilege
**Versions:** Windows 8.1 / Server 2012 R2 and later

This technique opens a named pipe on the target and triggers a connection to it via the [MS-RPRN][2] RPC Interface,
specifically by calling `RpcRemoteFindFirstPrinterChangeNotification`. Once the connection is received, the client is
impersonated using [ImpersonateNamedPipeClient][1] which elevates the listening process (Meterpreter) to
`NT AUTHORITY\SYSTEM`.

#### References

* https://github.com/itm4n/PrintSpoofer
* https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/

### 6 - Named Pipe Impersonation (EfsPotato Variant)
**Side Effects:** None
**Requirements:** Privilege: SeImpersonatePrivilege
**Versions:** Windows Vista / Server 2008 and later

This technique opens a named pipe on the target and triggers a connection to it via the [MS-EFSR][3] RPC Interface,
specifically by calling `EfsRpcEncryptFileSrv`. Once the connection is received, the client is impersonated using
[ImpersonateNamedPipeClient][1] which elevates the listening process (Meterpreter) to `NT AUTHORITY\SYSTEM`.

#### References

* https://github.com/zcgonvh/EfsPotato

## Scenarios

### Windows 10 x64 21H2 Running As NT AUTHORITY\NETWORK SERVICE

```
msf6 payload(windows/x64/meterpreter/reverse_tcp) > sessions -i -1
[*] Starting interaction with 1...

meterpreter > sysinfo
Computer        : DESKTOP-81CEH16
OS              : Windows 10 (10.0 Build 19044).
Architecture    : x64
System Language : en_US
Meterpreter     : x64/windows
meterpreter > getuid
Server username: NT AUTHORITY\NETWORK SERVICE
meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeAssignPrimaryTokenPrivilege
SeAuditPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeImpersonatePrivilege
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
SeShutdownPrivilege
SeTimeZonePrivilege
SeUndockPrivilege

meterpreter > getsystem -t 4
...got system via technique 4 (Named Pipe Impersonation (RPCSS variant)).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > 
```

[1]: https://docs.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
[2]: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1
[3]: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31
