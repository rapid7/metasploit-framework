## Vulnerable Application

  This module lists the Microsoft 365 Sharepoint/Onedrive endpoints that are being synchronised
  by the OneDrive Windows application. It will attempt to do this for every local user on the 
  system (subject to permissions) and will also create a CSV with the results in loot.

  A user can only have one OneDrive personal account synchronised, but can have many business
  accounts synchronised. In addition, within the business accounts, there can be several 'teamsites'
  (for example, MS Teams document libraries).

  This could highlight document libraries or repositories that contain sensitive information,
  or simply provide an additional source of information during an engagement. 

## Verification Steps

  1. Start msfconsole
  2. Get meterpreter session
  3. Type: ```use post/windows/gather/enum_onedrive```
  4. Type: ```set SESSION <session id>```
  5. Type: ```run```

## Options

  **SESSION**

  The session to run the module on.

## Scenarios

  ```
  msf6 post(windows/gather/enum_onedrive) > rerun
[*] Reloading module...
[*] Looking for OneDrive sync information for S-1-5-21-1058076759-3907379039-658025484-1001
[+] OneDrive sync information for S-1-5-21-1058076759-3907379039-658025484-1001


  Business1
  =========

    Business: 1
    ServiceEndpointUri: https://demo1-my.sharepoint.com/personal/stuart_mwrdemo_com/_api
    SPOResourceId: https://demo1-my.sharepoint.com/
    UserEmail: stuart@mwrdemo.com
    UserFolder: C:\Users\Stuart\OneDrive - MWRDemo
    UserName: Stuart

    | LibraryType: teamsite
    | LastModifiedTime: 2021-01-07T20:00:54
    | MountPoint: C:\Users\Stuart\Demo\Training
    | UrlNamespace: https://demo1.sharepoint.com/sites/Training/Shared Documents/

    | LibraryType: teamsite
    | LastModifiedTime: 2021-01-06T21:04:01
    | MountPoint: C:\Users\Stuart\Demo\Vault
    | UrlNamespace: https://demo1.sharepoint.com/sites/Vault/Private/

    | LibraryType: mysite
    | LastModifiedTime: 2021-01-07T20:00:54
    | MountPoint: C:\Users\Stuart\OneDrive - MWRDemo
    | UrlNamespace: https://demo1-my.sharepoint.com/personal/stuart_mwrdemo_com/Documents/

[+] OneDrive sync information saved to /usr/home/s/stuart/.msf4/loot/20210107203200_default_192.0.2.180_onedrive.syncinf_658363.txt in CSV format.
[*] Post module execution completed
  ```
