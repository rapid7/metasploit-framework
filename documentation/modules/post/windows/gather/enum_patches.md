
## Vulnerable Application

  This module will attempt to enumerate which patches are applied to a
  Windows system, as well as on which date they were applied, based on
  the result of the WMI query `SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering`.

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

### Windows 10 x64 v1909

  ```
  msf6 exploit(multi/handler) > use post/windows/gather/enum_patches
  msf6 post(windows/gather/enum_patches) > show options

  Module options (post/windows/gather/enum_patches):

    Name     Current Setting  Required  Description
    ----     ---------------  --------  -----------
    SESSION                   yes       The session to run this module on.

  msf6 post(windows/gather/enum_patches) > set SESSION 1
  SESSION => 1
  msf6 post(windows/gather/enum_patches) > run

  [*] Patch list saved to /home/gwillcox/.msf4/loot/20200902125729_default_172.29.215.21_enum_patches_495652.txt
  [+] KB4569751 installed on 8/17/2020
  [+] KB4497165 installed on 8/17/2020
  [+] KB4517245 installed on 4/10/2020
  [+] KB4537759 installed on 4/10/2020
  [+] KB4552152 installed on 4/10/2020
  [+] KB4561600 installed on 8/17/2020
  [+] KB4569073 installed on 8/17/2020
  [+] KB4565351 installed on 8/17/2020
  [*] Post module execution completed
  msf6 post(windows/gather/enum_patches) >
  ```
