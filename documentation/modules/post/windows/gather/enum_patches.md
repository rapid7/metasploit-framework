## Vulnerable Application

This module enumerates patches applied to a Windows system using the
WMI query: `SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering`.


## Verification Steps

1. Start msfconsole
2. Get meterpreter session
3. Do: `use post/windows/gather/enum_patches`
4. Do: `set SESSION <session id>`
5. Do: `run`

## Options


## Scenarios

### Windows 11 Pro 10.0.22000 Build 22000 x64

```
msf6 post(windows/gather/enum_patches) > set session 1
session => 1
msf6 post(windows/gather/enum_patches) > run

[*] Running module against WINDEV2110EVAL (192.168.200.140)

Installed Patches
=================

  HotFix ID  Install Date
  ---------  ------------
  KB5009469  2/27/2022
  KB5009641  2/26/2022
  KB5011493  3/5/2022

[*] Patch list saved to /root/.msf4/loot/20220911234321_default_192.168.200.140_enum_patches_485106.txt
[*] Post module execution completed
```

### Windows 7 SP1 x64

```
msf6 post(windows/gather/enum_patches) > set session 1
session => 1
msf6 post(windows/gather/enum_patches) > run

[*] Running module against TEST (192.168.200.190)

Installed Patches
=================

  HotFix ID  Install Date
  ---------  ------------
  KB2533623  3/29/2019
  KB2534111  2/1/2016
  KB2639308  3/29/2019
  KB2670838  3/29/2019
  KB2729094  3/29/2019
  KB2731771  3/29/2019
  KB2786081  3/29/2019
  KB2834140  3/29/2019
  KB2841134  3/29/2019
  KB2849696  3/29/2019
  KB2849697  3/29/2019
  KB2882822  3/29/2019
  KB2888049  3/29/2019
  KB2999226  9/4/2017
  KB958488   5/26/2017
  KB976902   11/21/2010

[*] Patch list saved to /root/.msf4/loot/20220911233948_default_192.168.200.190_enum_patches_697182.txt
[*] Post module execution completed
```

### Windows XP SP3 x86

```
msf6 post(windows/gather/enum_patches) > set session 1
session => 1
msf6 post(windows/gather/enum_patches) > run

[*] Running module against WINXP (192.168.200.164)

Installed Patches
=================

  HotFix ID  Install Date
  ---------  ------------
  KB811113   4/5/2013
  KB936929   4/5/2013
  Q147222

[*] Patch list saved to /root/.msf4/loot/20220911233635_default_192.168.200.164_enum_patches_552914.txt
[*] Post module execution completed
```
