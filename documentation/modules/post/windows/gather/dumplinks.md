
## Vulnerable Application

  The dumplinks module is a modified port of Harlan Carvey's lslnk.pl Perl script. This module will parse .lnk files from a user's
  Recent Documents folder and Microsoft Office's Recent Documents folder, if present. Windows creates these link files automatically
  for many common file types. The .lnk files contain time stamps, file locations, including share names, volume serial numbers, and more.

## Verification Steps

  1. Start msfconsole
  2. Get meterpreter session
  3. Do: ```use post/windows/gather/dumplinks```
  4. Do: ```set SESSION <session id>```
  5. Do: ```run```

## Options

  **SESSION**

  The session to run the module on.


## Scenarios

  ```
  [*] Meterpreter session 1 opened (192.168.1.3:4444 -> 192.168.1.10:49160) at 2019-12-11 15:45:16 -0700

  msf > use post/windows/gather/dumplinks
  msf post(windows/gather/dumplinks) > set SESSION 1
    SESSION => 1
  msf post(windows/gather/dumplinks) > run

    [*] Running module against TEST-PC
    [*] Extracting lnk files for user TEST at C:\Users\TEST\AppData\Roaming\Microsoft\Windows\Recent\...
    [*] Processing: C:\Users\TEST\AppData\Roaming\Microsoft\Windows\Recent\myPasswords.lnk.
    [*] Processing: C:\Users\TEST\AppData\Roaming\Microsoft\Windows\Recent\Network and Internet.lnk.
    [*] No Recent Office files found for user TEST. Nothing to do.
    [*] Post module execution completed
  ```

## Example of looted .lnk output

  ```
  [*] exec: cat /root/.msf4/loot/20191211154832_default_192.168.1.10_host.windows.lnk_124491.txt

  C:\Users\TEST\AppData\Roaming\Microsoft\Windows\Recent\myPasswords.lnk:
          Access Time       = 2019-12-11 23:44:39 -0700
          Creation Date     = 2019-12-11 23:44:39 -0700
          Modification Time = 2019-12-11 23:44:39 -0700
  Contents of C:\Users\TEST\AppData\Roaming\Microsoft\Windows\Recent\myPasswords.lnk:
          Flags:
                  Shell Item ID List exists.
                  Shortcut points to a file or directory.
                  The shortcut has a relative path string.
                  The shortcut has working directory.
          Attributes:
                  Target was modified since last backup.
          Target file's MAC Times stored in lnk file:
                  Creation Time     = 2019-12-11 23:44:30 -0700. (UTC)
                  Modification Time = 2019-12-11 23:44:30 -0700. (UTC)
                  Access Time       = 2019-12-11 23:44:30 -0700. (UTC)
          ShowWnd value(s):
                  SW_NORMAL.
                  SW_SHOWMAXIMIZED.
                  SW_SHOW.
                  SW_SHOWMINNOACTIVE.
                  SW_RESTORE.
        Target file's MAC Times stored in lnk file:
                  Creation Time     = 2019-12-11 23:44:30 -0700. (UTC)
                  Modification Time = 2019-12-11 23:44:30 -0700. (UTC)
                  Access Time       = 2019-12-11 23:44:30 -0700. (UTC)
        Shortcut file is on a local volume.
                  Volume Name =
                  Volume Type = Fixed
                  Volume SN   = 0x548EF20B
        Target path = C:\Users\TEST\Desktop\myPasswords.txt&..\..\..\..\..\Desktop\myPasswords.txtC:\Users\TEST\Desktop(
      ```
